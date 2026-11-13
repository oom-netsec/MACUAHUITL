package metrics

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/metrics"
	"github.com/oom-netsec/MACUAHUITL/internal/platform/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

// GetPortStatus devuelve el estado de los puertos físicos: de un trabajo de Patrol (job_id o dir) o, sin
// ellos, en vivo por SSH.
func (s *svc) GetPortStatus(ctx context.Context, r *v1.GetPortStatusRequest) (*v1.GetPortStatusResponse, error) {
	s.d.MarkActive()
	if r.JobId != "" || r.Dir != "" {
		dir, err := s.jobDir(ctx, r.JobId, r.Dir)
		if err != nil {
			return nil, err
		}
		s.d.Audit("metrics.ports", dir, "device="+r.Device)
		pd, err := metrics.PortsFromJob(dir, r.Device)
		if err != nil {
			return nil, service.ErrFrom(ctx, codes.FailedPrecondition, err)
		}
		pd.PortStatus = pd.PortStatus.Localize(i18n.Locale(ctx))
		return portResponse("job", pd), nil
	}
	return s.livePorts(ctx, r)
}

func portResponse(src string, pd metrics.PortDevice) *v1.GetPortStatusResponse {
	out := &v1.GetPortStatusResponse{Source: src, Address: pd.Address, Hostname: pd.Hostname, Warnings: pd.Warnings}
	if !pd.At.IsZero() {
		out.AtMs = pd.At.UnixMilli()
	}
	for _, p := range pd.Ports {
		out.Ports = append(out.Ports, &v1.PortInfo{Name: p.Name, Kind: p.Kind, Module: int32(p.Module), Stack: int32(p.Stack), Number: int32(p.Number), Description: p.Description,
			Status: p.Status, Vlan: p.VLAN, Duplex: p.Duplex, Speed: p.Speed, DuplexMode: p.DuplexMode, SpeedMbps: int32(p.SpeedMbps), AutoNegotiated: p.AutoNeg, Type: p.Type,
			Trunk: p.Trunk, TrunkNative: p.TrunkNative, Channel: p.Channel, ChannelFlags: p.ChannelFlags})
	}
	for _, c := range pd.Channels {
		ch := &v1.PortChannel{Name: c.Name, State: c.State, Protocol: c.Protocol}
		for _, m := range c.Members {
			ch.Members = append(ch.Members, &v1.ChannelMember{Port: m.Port, Flags: m.Flags})
		}
		out.Channels = append(out.Channels, ch)
	}
	return out
}

// connErr traduce los errores de conexión a códigos gRPC; la huella de una llave nueva va en el mensaje.
func connErr(ctx context.Context, err error) error {
	var he *transport.HostKeyError
	switch {
	case errors.As(err, &he):
		return service.ErrFrom(ctx, codes.FailedPrecondition, err)
	case errors.Is(err, transport.ErrAuth), errors.Is(err, transport.ErrEgressDenied):
		return service.ErrFrom(ctx, codes.PermissionDenied, err)
	}
	if s := service.VaultErr(err); status.Code(s) != codes.Internal {
		return s
	}
	return service.ErrFrom(ctx, codes.Unavailable, err)
}

// livePorts abre una sesión SSH de solo lectura: guard con Revoke, llave de host estricta, tres comandos de
// la lista de lectura (CheckDenied) y se cierra. La bitácora lleva el equipo y la credencial, nunca secretos.
func (s *svc) livePorts(ctx context.Context, r *v1.GetPortStatusRequest) (*v1.GetPortStatusResponse, error) {
	// El plazo de cada comando es de inactividad (con tope de 30 min): la consulta en vivo completa se acota aquí.
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	host := strings.TrimSpace(r.Device)
	if host == "" || strings.HasPrefix(host, "-") || strings.ContainsAny(host, " \t\r\n/") || r.Port > 0xffff {
		return nil, service.Err(ctx, codes.InvalidArgument, "metrics.svc.live_target", nil)
	}
	if r.CredentialId == "" {
		return nil, service.Err(ctx, codes.InvalidArgument, "metrics.svc.live_cred", nil)
	}
	for _, c := range metrics.PortCommands { // la lista es fija, pero un cambio futuro no debe saltarse la regla de solo lectura
		if err := playbook.CheckDenied("ios-xe", c); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}
	v := s.d.Vault()
	if v == nil || !v.Unlocked() {
		return nil, service.Err(ctx, codes.FailedPrecondition, "metrics.svc.vault_locked", nil)
	}
	cred, err := v.Get(r.CredentialId)
	if err != nil {
		return nil, service.VaultErr(err)
	}
	port := uint16(r.Port)
	if port == 0 {
		port = 22
	}
	run := "ports-" + service.NewID()
	g := s.d.Guard()
	if err := g.Allow(ctx, run, []string{host}); err != nil {
		cred.Enable.Destroy()
		cred.Password.Destroy()
		cred.SSHKey.Destroy()
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	defer g.Revoke(run)
	s.d.Audit("metrics.ports.live.start", host, fmt.Sprintf("run=%s port=%d credential=%q legacy_ssh=%t", run, port, r.CredentialId, r.LegacySsh))
	fail := func(err error) (*v1.GetPortStatusResponse, error) {
		s.d.Audit("metrics.ports.live.failed", host, fmt.Sprintf("run=%s reason=%q guard=revoked", run, i18n.English(err)))
		return nil, connErr(ctx, err)
	}
	acc := map[string]bool{}
	for _, fp := range r.AcceptedHostKeyFingerprints {
		acc[fp] = true
	}
	hk := s.d.Hosts().Callback(transport.HostKeyPolicy{Accepted: acc}, func(en audit.Entry) { s.d.Audit(en.Action, en.Target, en.Detail) })
	sess, err := transport.OpenSSH(ctx, g, run, host, port, cred, hk, transport.SSHOptions{AllowLegacy: r.LegacySsh, OnLegacy: func(n string) { s.d.Audit("metrics.ssh.legacy", host, n) }})
	if err != nil {
		cred.Enable.Destroy()
		return fail(err)
	}
	defer sess.Close()
	rd, wr, err := sess.Shell()
	if err != nil {
		cred.Enable.Destroy()
		return fail(err)
	}
	drv := iosxe.New()
	defer drv.Close()
	if err := drv.Open(ctx, rd, wr, cred.Enable); err != nil {
		return fail(err)
	}
	if p, err := drv.Detect(ctx); err != nil || (p != "ios-xe" && p != "ios") {
		if err == nil {
			err = i18n.New("metrics.svc.platform", i18n.A("platform", p))
		}
		return fail(err)
	}
	run1 := func(cmd string) (string, bool, error) {
		o, err := drv.Run(ctx, cmd, 60*time.Second)
		return o.Text, !o.Invalid, err
	}
	var in metrics.PortTexts
	at := time.Now().UTC()
	for _, cmd := range metrics.PortCommands {
		text, ok, err := run1(cmd)
		if err != nil {
			return fail(err)
		}
		switch cmd {
		case metrics.CmdPortStatus:
			in.Status = text
			if !ok {
				in.Status = ""
			}
		case metrics.CmdTrunk:
			in.Trunk, in.HaveTrunk = text, ok
		case metrics.CmdChannels:
			in.Channels, in.HaveChannels = text, ok
		}
	}
	ps := metrics.BuildPorts(in).Localize(i18n.Locale(ctx))
	s.d.Audit("metrics.ports.live", host, fmt.Sprintf("run=%s ports=%d channels=%d guard=revoked", run, len(ps.Ports), len(ps.Channels)))
	return portResponse("live", metrics.PortDevice{PortStatus: ps, Address: host, Hostname: drv.Hostname(), At: at}), nil
}
