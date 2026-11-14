package patrol

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

// Progress es lo que RunDevice informa en vivo; el núcleo lo traduce a eventos.
type Progress struct {
	Target, State, Command string
	Index, Total           int
	Bytes                  int64
	Detail                 string
	Err                    error // el error de Detail, para darlo en el idioma del suscriptor; nil si Detail no sale de un error
}

type HostKeyChange struct {
	Target, Old, New string
}

type DeviceResult struct {
	Target             Target
	Round              int
	Hostname, Platform string
	State              string // completed, failed, skipped
	Detail             string
	DetailErr          error `json:"-"` // el error de Detail, para darlo en el idioma del cliente (i18n.In)
	Commands, Invalid  int
	// Skipped: comandos que no corren en la plataforma detectada (platforms: del playbook); van en el manifest.
	Skipped []string `json:",omitempty"`
	// Ran: IDs que de verdad corrieron cuando difieren de los elegidos (gemelo de la plataforma); va en el manifest.
	Ran            []string       `json:",omitempty"`
	ChangedHostKey *HostKeyChange `json:",omitempty"`
}

// auditResult registra el resultado del equipo en la ronda (spec §12.2). Si la auditoría
// no se puede escribir, el equipo cuenta como fallido: no hay evidencia sin rastro.
func auditResult(ctx context.Context, d Deps, jobID string, res DeviceResult) DeviceResult {
	detail := res.Detail // la auditoría va siempre en inglés
	if res.DetailErr != nil {
		detail = i18n.English(res.DetailErr)
	}
	_, err := d.Audit.Append(ctx, audit.Entry{Actor: "patrol", Action: "device.round", Target: hostport(res.Target),
		Detail: fmt.Sprintf("job=%s round=%d state=%s commands=%d invalid=%d error=%q", jobID, res.Round, res.State, res.Commands, res.Invalid, detail)})
	if err != nil {
		res.State, res.DetailErr = "failed", i18n.New("patrol.err.audit", i18n.A("error", err.Error()))
		res.Detail = res.DetailErr.Error()
	}
	return res
}

// ErrWindowEnded es la causa del contexto de un equipo cuando llega el fin de la ventana del trabajo:
// lo que siga corriendo se corta y el equipo falla con este error.
var ErrWindowEnded = i18n.New("patrol.err.window_ended", nil)

// windowEnded sustituye el error de un comando o conexión cortados por el fin de la ventana.
func windowEnded(ctx context.Context, err error) error {
	if (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) && errors.Is(context.Cause(ctx), ErrWindowEnded) {
		return ErrWindowEnded
	}
	return err
}

// RunDevice corre una ronda contra un equipo y escribe sus outputs en w.
func RunDevice(ctx context.Context, d Deps, jobID string, s Spec, w *Writer, round int, t Target, emit func(Progress)) (res DeviceResult) {
	res = DeviceResult{Target: t, Round: round}
	hp := hostport(t)
	emit(Progress{Target: hp, State: "connecting"})
	base := auditor(context.WithoutCancel(ctx), d) // un corte en pleno handshake no debe dejar eventos sin auditar
	onEvent := func(e audit.Entry) {
		if ch := changeOf(e, hp); ch != nil {
			res.ChangedHostKey = ch
		}
		base(e)
	}
	defer func() { res = auditResult(context.WithoutCancel(ctx), d, jobID, res) }() // con la ventana vencida también debe quedar rastro
	c, err := connect(ctx, d, jobID, s, t, transport.HostKeyPolicy{AcceptChanged: s.AcceptChangedHostKeys}, onEvent, d.PrimaryVerified[hp], d.backoff())
	if err != nil {
		err = windowEnded(ctx, err)
		res.State, res.Detail, res.DetailErr = "failed", err.Error(), err
		if step(err) == "host_key" {
			res.State = "skipped"
		}
		emit(Progress{Target: hp, State: res.State, Detail: res.Detail, Err: res.DetailErr})
		return res
	}
	defer c.close()
	res.Hostname, res.Platform = c.drv.Hostname(), c.platform
	cmds, skipped, err := commands(s, c.platform, d.Playbooks, d.MissingPack)
	if err != nil {
		res.State, res.Detail, res.DetailErr = "failed", err.Error(), err
		emit(Progress{Target: hp, State: res.State, Detail: res.Detail, Err: res.DetailErr})
		return res
	}
	res.Skipped = skipped
	if ran, _ := resolve(s, c.platform, d.Playbooks, d.MissingPack); len(ran) > 0 {
		for _, p := range ran {
			res.Ran = append(res.Ran, p.ID)
		}
		if slices.Equal(res.Ran, s.PlaybookIDs) {
			res.Ran = nil
		}
	}
	dev := Device{Host: res.Hostname, IP: t.Address, Platform: c.platform}
	roundStart := d.Now()
	var bytes int64
	for i, cmd := range cmds {
		emit(Progress{Target: hp, State: "running", Command: cmd.Text, Index: i + 1, Total: len(cmds), Bytes: bytes})
		cctx, cancel := context.WithTimeout(ctx, maxCmd(cmd.Timeout)) // el timeout es de inactividad: esto es el tope total
		out, runErr := c.drv.Run(cctx, cmd.Text, cmd.Timeout)
		cancel()
		runErr = windowEnded(ctx, runErr)
		bytes += int64(len(out.Text))
		if out.Invalid {
			res.Invalid++
		}
		out.Incomplete = runErr != nil
		if werr := w.Write(dev, round, roundStart, out, !s.DisableMasking); werr != nil {
			runErr = werr
		}
		res.Commands++
		if runErr != nil {
			res.State, res.Detail, res.DetailErr = "failed", runErr.Error(), runErr
			emit(Progress{Target: hp, State: res.State, Detail: res.Detail, Err: res.DetailErr})
			return res
		}
	}
	res.State = "completed"
	emit(Progress{Target: hp, State: res.State, Index: len(cmds), Total: len(cmds), Bytes: bytes})
	return res
}

// maxCmd es el tope total de un comando: 5 veces su timeout de inactividad, y no menos de 5 minutos.
func maxCmd(timeout time.Duration) time.Duration { return max(5*timeout, 5*time.Minute) }
