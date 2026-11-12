package patrol

import (
	"context"
	"fmt"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

// Progress es lo que RunDevice informa en vivo; el núcleo lo traduce a eventos.
type Progress struct {
	Target, State, Command string
	Index, Total           int
	Bytes                  int64
	Detail                 string
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
	Commands, Invalid  int
	// Skipped: comandos que no corren en la plataforma detectada (platforms: del playbook); van en el manifest.
	Skipped        []string       `json:",omitempty"`
	ChangedHostKey *HostKeyChange `json:",omitempty"`
}

// auditResult registra el resultado del equipo en la ronda (spec §12.2). Si la auditoría
// no se puede escribir, el equipo cuenta como fallido: no hay evidencia sin rastro.
func auditResult(ctx context.Context, d Deps, jobID string, res DeviceResult) DeviceResult {
	_, err := d.Audit.Append(ctx, audit.Entry{Actor: "patrol", Action: "device.round", Target: hostport(res.Target),
		Detail: fmt.Sprintf("job=%s round=%d state=%s commands=%d invalid=%d %s", jobID, res.Round, res.State, res.Commands, res.Invalid, res.Detail)})
	if err != nil {
		res.State, res.Detail = "failed", "audit: "+err.Error()
	}
	return res
}

// RunDevice corre una ronda contra un equipo y escribe sus outputs en w.
func RunDevice(ctx context.Context, d Deps, jobID string, s Spec, w *Writer, round int, t Target, emit func(Progress)) (res DeviceResult) {
	res = DeviceResult{Target: t, Round: round}
	hp := hostport(t)
	emit(Progress{Target: hp, State: "connecting"})
	base := auditor(ctx, d)
	onEvent := func(e audit.Entry) {
		if ch := changeOf(e, hp); ch != nil {
			res.ChangedHostKey = ch
		}
		base(e)
	}
	defer func() { res = auditResult(ctx, d, jobID, res) }()
	c, err := connect(ctx, d, jobID, s, t, transport.HostKeyPolicy{AcceptChanged: s.AcceptChangedHostKeys}, onEvent, d.PrimaryVerified[hp], d.backoff())
	if err != nil {
		res.State, res.Detail = "failed", err.Error()
		if step(err) == "host_key" {
			res.State = "skipped"
		}
		emit(Progress{Target: hp, State: res.State, Detail: res.Detail})
		return res
	}
	defer c.close()
	res.Hostname, res.Platform = c.drv.Hostname(), c.platform
	cmds, skipped, err := commands(s, c.platform, d.Playbooks)
	if err != nil {
		res.State, res.Detail = "failed", err.Error()
		emit(Progress{Target: hp, State: res.State, Detail: res.Detail})
		return res
	}
	res.Skipped = skipped
	dev := Device{Host: res.Hostname, IP: t.Address, Platform: c.platform}
	roundStart := d.Now()
	var bytes int64
	for i, cmd := range cmds {
		emit(Progress{Target: hp, State: "running", Command: cmd.Text, Index: i + 1, Total: len(cmds), Bytes: bytes})
		out, runErr := c.drv.Run(ctx, cmd.Text, cmd.Timeout)
		bytes += int64(len(out.Text))
		if out.Invalid {
			res.Invalid++
		}
		if werr := w.Write(dev, round, roundStart, out, !s.DisableMasking); werr != nil {
			runErr = werr
		}
		res.Commands++
		if runErr != nil {
			res.State, res.Detail = "failed", runErr.Error()
			emit(Progress{Target: hp, State: res.State, Detail: res.Detail})
			return res
		}
	}
	res.State = "completed"
	emit(Progress{Target: hp, State: res.State, Index: len(cmds), Total: len(cmds), Bytes: bytes})
	return res
}
