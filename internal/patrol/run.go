package patrol

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/mask"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
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
	// Context: el contexto del que salió la evidencia ("system" o el nombre) cuando el destino pidió changeto.
	Context           string `json:",omitempty"`
	State             string // completed, partial, failed, skipped
	Detail            string
	DetailErr         error `json:"-"` // el error de Detail, para darlo en el idioma del cliente (i18n.In)
	Commands, Invalid int
	// CutCommands: los comandos que se cortaron (timeout o sesión caída), en orden, y Reconnects las reconexiones que
	// hizo la ronda para seguir. Van en el manifest.
	CutCommands []string `json:",omitempty"`
	Reconnects  int      `json:",omitempty"`
	// Skipped: comandos que no corren en la plataforma detectada (platforms: del playbook); van en el manifest.
	Skipped []string `json:",omitempty"`
	// Ran: IDs que de verdad corrieron cuando difieren de los elegidos (gemelo de la plataforma); va en el manifest.
	Ran []string `json:",omitempty"`
	// Requested: texto expandido de cada comando que pidió más de un playbook -> sus IDs. Corrió una sola vez.
	Requested      map[string][]string `json:",omitempty"`
	ChangedHostKey *HostKeyChange      `json:",omitempty"`
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

// windowEnded sustituye el error de un comando o conexión cortados por el fin de la ventana. El driver envuelve
// ctx.Err() en su ErrPromptTimeout, así que basta con reconocer el error del contexto.
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
		if ch := changeOf(e, hp); ch != nil && res.ChangedHostKey == nil { // se guarda la primera: la reconexión no la pisa
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
	defer func() { // c cambia al reconectar: se cierra la última sesión (nil si una reconexión falló y ya cerró la vieja)
		if c != nil {
			c.close()
		}
	}()
	res.Hostname, res.Platform = c.drv.Hostname(), c.platform
	serials := serialsOf(c.drv)
	entryHost := res.Hostname // el de la sesión antes del changeto: una sesión nueva llega ahí, no al contexto
	cmds, skipped, requested, err := plan(s, c.platform, d.Playbooks, d.MissingPack)
	if err != nil {
		res.State, res.Detail, res.DetailErr = "failed", err.Error(), err
		emit(Progress{Target: hp, State: res.State, Detail: res.Detail, Err: res.DetailErr})
		return res
	}
	res.Skipped, res.Requested = skipped, requested
	var pre []string
	evidence := map[string]bool{} // textos que algún playbook o los comandos propios piden como evidencia (no solo como Pre)
	if ran, _ := resolve(s, c.platform, d.Playbooks, d.MissingPack); len(ran) > 0 {
		for _, p := range ran {
			pre = append(pre, p.Pre...)
			res.Ran = append(res.Ran, p.ID)
			if cs, err := p.Expand(paramsOf(p, s.Params)); err == nil {
				for _, c := range cs {
					evidence[c.Text] = true
				}
			}
		}
		if slices.Equal(res.Ran, s.PlaybookIDs) {
			res.Ran = nil
		}
	}
	if s.CustomCommands != "" {
		if p, err := playbook.Ephemeral(c.platform, s.CustomCommands); err == nil {
			for _, cmd := range p.Commands {
				evidence[cmd.Text] = true
			}
		}
	}
	if t.Context != "" {
		sw, _ := c.drv.(platform.ContextSwitcher)
		entry := ""
		if sw != nil {
			entry = sw.Prompt().Context
		}
		// Vuelta al contexto de entrada, aunque haya error o corte (c cambia al reconectar). Va después del cierre de c: corre antes.
		defer func() {
			if c != nil {
				leaveContext(ctx, d, jobID, hp, round, c, entry)
			}
		}()
		if err := enterContext(ctx, d, jobID, hp, round, c, t.Context); err != nil {
			err = windowEnded(ctx, err)
			res.State, res.Detail, res.DetailErr = "failed", err.Error(), err
			emit(Progress{Target: hp, State: res.State, Detail: res.Detail, Err: res.DetailErr})
			return res
		}
		res.Hostname, res.Context = c.drv.Hostname(), t.Context
	}
	dev := Device{Host: res.Hostname, IP: t.Address, Port: t.Port, Platform: c.platform}
	roundStart := d.Now()
	var bytes int64
	complete := 0 // comandos con salida completa y que no es inválida
	var firstCut error
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
		out.Incomplete = out.Incomplete || runErr != nil
		werr := w.Write(dev, round, roundStart, out, !s.DisableMasking)
		cutErr := runErr
		if werr != nil {
			runErr = werr
		}
		res.Commands++
		if runErr == nil && !out.Invalid && (evidence[cmd.Text] || !slices.Contains(pre, cmd.Text)) { // los Pre son ajustes de sesión, no evidencia
			complete++
		}
		// Una cancelación (fin de ventana o trabajo cancelado) no es un corte del equipo.
		cut := runErr != nil && ctx.Err() == nil && (errors.Is(cutErr, platform.ErrPromptTimeout) || errors.Is(cutErr, platform.ErrClosed))
		if cut && firstCut == nil {
			firstCut = cutErr
		}
		shown := cmd.Text // el comando cortado va a la auditoría, al detalle y al manifest: con el mismo enmascarado que la evidencia
		if !s.DisableMasking {
			shown = mask.Cmd(c.platform, cmd.Text)
		}
		if cut && werr == nil && res.Reconnects < maxReconnects && i < len(cmds)-1 && !errors.Is(cutErr, ErrWindowEnded) {
			// Un comando cortado no se reintenta (puede seguir corriendo en la sesión vieja): se reabre y sigue el siguiente.
			// En el último no hay nada que seguir: no se reconecta y el equipo queda partial.
			res.CutCommands = append(res.CutCommands, shown)
			res.Reconnects++
			// El fallo de auditoría aquí se ignora, como en auditor(): lo atrapa el device.round final.
			d.Audit.Append(context.WithoutCancel(ctx), audit.Entry{Actor: "patrol", Action: "device.reconnect", Target: hp,
				Detail: fmt.Sprintf("job=%s round=%d command=%q cause=%q attempt=%d", jobID, round, shown, i18n.English(cutErr), res.Reconnects)})
			emit(Progress{Target: hp, State: "connecting"})
			c.close()
			c = nil
			nc, err := connect(ctx, d, jobID, s, t, transport.HostKeyPolicy{AcceptChanged: s.AcceptChangedHostKeys}, onEvent, d.PrimaryVerified[hp], d.backoff())
			var ns []string
			if err == nil {
				ns = serialsOf(nc.drv)
			}
			other, note := false, false
			if err == nil {
				other, note = otherDevice(entryHost, res.Platform, serials, nc.drv.Hostname(), nc.platform, ns)
			}
			if note { // la interseccion de series dice que es el mismo equipo lógico (switchover de un stack), pero el conjunto cambió
				d.Audit.Append(context.WithoutCancel(ctx), audit.Entry{Actor: "patrol", Action: "device.reconnect", Target: hp,
					Detail: fmt.Sprintf("job=%s round=%d serial set changed: %v -> %v", jobID, round, serials, ns)})
			}
			if other {
				// Otro equipo tras la misma IP (un par en failover con la llave replicada): no se escribe nada más en la carpeta del primero.
				err = i18n.New("patrol.err.reconnect_other_device", i18n.A("from", identOf(entryHost, res.Platform, serials), "to", identOf(nc.drv.Hostname(), nc.platform, ns)))
				nc.close()
			} else if err == nil { // si en la reconexión cambió la llave de host, el equipo queda failed y no skipped: ya hay evidencia escrita
				c = nc
				err = rerunPre(ctx, c, pre, cmds[:i])
			}
			if err == nil && t.Context != "" { // la sesión nueva entra por el contexto de siempre: se repite el changeto
				err = enterContext(ctx, d, jobID, hp, round, c, t.Context)
			}
			if err != nil {
				err = windowEnded(ctx, err)
				res.State, res.Detail, res.DetailErr = "failed", err.Error(), err
				emit(Progress{Target: hp, State: res.State, Detail: res.Detail, Err: res.DetailErr})
				return res
			}
			continue
		}
		if runErr != nil {
			if cut && werr == nil && !errors.Is(cutErr, ErrWindowEnded) && i == len(cmds)-1 {
				res.CutCommands = append(res.CutCommands, shown) // el último cortado: partial, sin reconectar (partial o failed lo decide el cierre)
				continue
			}
			if cut {
				res.CutCommands = append(res.CutCommands, shown)
			}
			res.State, res.Detail, res.DetailErr = "failed", runErr.Error(), runErr
			emit(Progress{Target: hp, State: res.State, Detail: res.Detail, Err: res.DetailErr})
			return res
		}
	}
	res.State = "completed"
	if len(res.CutCommands) > 0 && complete == 0 { // sin una sola salida completa y válida no hay nada que conservar: failed
		res.State, res.Detail, res.DetailErr = "failed", firstCut.Error(), firstCut
		emit(Progress{Target: hp, State: res.State, Detail: res.Detail, Err: res.DetailErr})
		return res
	}
	if len(res.CutCommands) > 0 {
		res.State = "partial"
		res.DetailErr = i18n.New("patrol.dev.partial", i18n.A("cut", len(res.CutCommands), "reconnects", res.Reconnects, "first", res.CutCommands[0]))
		res.Detail = res.DetailErr.Error()
	}
	emit(Progress{Target: hp, State: res.State, Index: len(cmds), Total: len(cmds), Bytes: bytes, Detail: res.Detail, Err: res.DetailErr})
	return res
}

// maxReconnects son las reconexiones que hace un equipo en una ronda; el corte siguiente lo deja en failed.
const maxReconnects = 2

// rerunPre repite en la sesión nueva los Pre de los playbooks (ajustes de sesión como la paginación) que ya corrieron
// antes del corte; su salida no va a la evidencia. Open ya apaga la paginación del driver.
func rerunPre(ctx context.Context, c *connected, pre []string, done []playbook.Command) error {
	for _, p := range pre {
		if !slices.ContainsFunc(done, func(x playbook.Command) bool { return x.Text == p }) {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, maxCmd(60*time.Second))
		_, err := c.drv.Run(cctx, p, 60*time.Second)
		cancel()
		if err != nil {
			return err
		}
	}
	return nil
}

// maxCmd es el tope total de un comando: 5 veces su timeout de inactividad, y no menos de 5 minutos.
func maxCmd(timeout time.Duration) time.Duration { return max(5*timeout, 5*time.Minute) }

// serialsOf son las series que vio Detect, si el driver las expone.
func serialsOf(d platform.Driver) []string {
	if s, ok := d.(interface{ Serials() []string }); ok {
		return s.Serials()
	}
	return nil
}

func identOf(host, platform string, serials []string) string {
	return host + " (" + strings.TrimSpace(platform+" "+strings.Join(serials, " ")) + ")"
}

// otherDevice dice si la sesión nueva es de otro equipo, y si el conjunto de series cambió dentro del mismo equipo (note).
// El prompt no sirve para decidirlo (un par en failover lo repite; un clúster con «prompt hostname state» lo cambia), así
// que se comparan los CONJUNTOS de series: con intersección es el mismo equipo lógico (un stack tras un switchover cambia la
// activa y quizá un miembro); disjuntos son dos unidades distintas (el par ASA) y el equipo falla. Si a alguna sesión le
// falta la serie (AireOS, ISE) se compara el hostname y la plataforma. Limitación conocida: tras un switchover de VSS/SVL,
// 9800 HA SSO o un N7K con dos supervisoras, si el show version de la activa no lista la serie de la otra, la reconexión
// puede parar con «otro equipo»; es una falla del lado seguro (se repite el trabajo) y falta validarla en laboratorio.
func otherDevice(oldHost, oldPlatform string, oldSerials []string, newHost, newPlatform string, newSerials []string) (other, note bool) {
	if oldPlatform != newPlatform {
		return true, false
	}
	if len(oldSerials) == 0 || len(newSerials) == 0 {
		return oldHost != newHost, false
	}
	for _, s := range oldSerials {
		if slices.Contains(newSerials, s) {
			return false, !slices.Equal(oldSerials, newSerials)
		}
	}
	return true, false
}
