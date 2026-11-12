package patrol

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

type LoginResult struct {
	ChangedHostKey *HostKeyChange // llave cambiada que el ingeniero aceptó en este Login Test
	Target         string
	Passed         bool
	FailedStep     string // tcp, host_key, auth, privilege, prompt, platform
	Detail         string
	DetailErr      error // el error de Detail, para darlo en el idioma del cliente (i18n.In); nil si Detail no sale de un error
	Platform       string
	Fingerprint    string
}

func hostport(t Target) string {
	if a, err := netip.ParseAddr(t.Address); err == nil {
		return netip.AddrPortFrom(a, port(t)).String()
	}
	return t.Address + ":" + strconv.Itoa(int(port(t)))
}

func addresses(s Spec) []string {
	out := make([]string, len(s.Targets))
	for i, t := range s.Targets {
		out[i] = t.Address
	}
	return out
}

func step(err error) string {
	var he *transport.HostKeyError
	switch {
	case errors.As(err, &he), errors.Is(err, transport.ErrKnownHosts):
		return "host_key"
	case errors.Is(err, transport.ErrAuth):
		return "auth"
	case errors.Is(err, platform.ErrEnableFailed):
		return "privilege"
	case errors.Is(err, platform.ErrPromptTimeout), errors.Is(err, platform.ErrClosed):
		return "prompt"
	case errors.Is(err, platform.ErrUnknownPlatform):
		return "platform"
	}
	return "tcp"
}

// connected es una sesión lista: shell abierto, privilegiado y con plataforma detectada.
type connected struct {
	sess     *transport.Session
	drv      platform.Driver
	platform string
}

func (c *connected) close() {
	c.drv.Close()
	c.sess.Close()
}

// connect recorre los pasos de spec §12.2 con reintentos solo por falla de conexión
// (nunca por autenticación ni por llave de host). Destruye las credenciales que usa.
func connect(ctx context.Context, d Deps, jobID string, s Spec, t Target, hk transport.HostKeyPolicy, onEvent func(audit.Entry), allowFallback bool, retries []time.Duration) (*connected, error) {
	c, err := connectOnce(ctx, d, jobID, s, t, hk, onEvent, allowFallback)
	for _, wait := range retries {
		if err == nil || step(err) != "tcp" || errors.Is(err, transport.ErrEgressDenied) || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		c, err = connectOnce(ctx, d, jobID, s, t, hk, onEvent, allowFallback)
	}
	return c, err
}

func connectOnce(ctx context.Context, d Deps, jobID string, s Spec, t Target, hk transport.HostKeyPolicy, onEvent func(audit.Entry), allowFallback bool) (*connected, error) {
	primary, fallback := credentialsFor(s, t)
	cb := d.Hosts.Callback(hk, onEvent)
	open := func(id string) (*transport.Session, vault.Credential, error) {
		cred, err := d.Vault.Get(id)
		if err != nil {
			return nil, cred, i18n.Wrap("patrol.err.credential", nil, err)
		}
		sess, err := transport.OpenSSH(ctx, d.Guard, jobID, t.Address, port(t), cred, cb, transport.SSHOptions{})
		if err != nil {
			cred.Enable.Destroy()
		}
		return sess, cred, err
	}
	sess, cred, err := open(primary)
	if errors.Is(err, transport.ErrAuth) && fallback != "" && allowFallback {
		onEvent(audit.Entry{Action: "auth.fallback", Target: hostport(t), Detail: jobID})
		sess, cred, err = open(fallback)
	}
	if err != nil {
		return nil, err
	}
	r, w, err := sess.Shell()
	if err != nil {
		cred.Enable.Destroy()
		sess.Close()
		return nil, err
	}
	drv := d.driver()
	c := &connected{sess: sess, drv: drv}
	if err := drv.Open(ctx, r, w, cred.Enable); err != nil {
		c.close()
		return nil, err
	}
	p, err := drv.Detect(ctx)
	if err != nil {
		c.close()
		return nil, err
	}
	c.platform = p
	return c, nil
}

// LoginTest prueba cada equipo. Interactivo: una llave desconocida devuelve su huella para
// confirmar, y las huellas en accepted se guardan. Silencioso: aplica la política del trabajo.
func LoginTest(ctx context.Context, d Deps, jobID string, s Spec, interactive bool, accepted map[string]bool) []LoginResult {
	out := make([]LoginResult, len(s.Targets))
	if err := d.Guard.Allow(ctx, jobID, addresses(s)); err != nil {
		for i, t := range s.Targets {
			out[i] = LoginResult{Target: hostport(t), FailedStep: "tcp", Detail: err.Error(), DetailErr: err}
		}
		return out
	}
	pol := transport.HostKeyPolicy{AcceptChanged: s.AcceptChangedHostKeys}
	if interactive {
		pol = transport.HostKeyPolicy{Accepted: accepted}
	}
	for i, t := range s.Targets {
		r := LoginResult{Target: hostport(t)}
		base := auditor(ctx, d)
		onEvent := func(e audit.Entry) {
			if ch := changeOf(e, r.Target); ch != nil {
				r.ChangedHostKey = ch
			}
			base(e)
		}
		// Sin respaldo ni reintentos: el Login Test dice la verdad sobre la credencial principal.
		c, err := connect(ctx, d, jobID, s, t, pol, onEvent, false, nil)
		if err == nil {
			r.Platform = c.platform
			_, _, err = commands(s, c.platform, d.Playbooks)
			if err != nil {
				r.FailedStep = "platform"
			}
			c.close()
		} else {
			r.FailedStep = step(err)
		}
		if err != nil {
			r.Detail, r.DetailErr = err.Error(), err
			var he *transport.HostKeyError
			if errors.As(err, &he) {
				r.Fingerprint = he.Fingerprint
			}
		}
		r.Passed = err == nil
		out[i] = r
	}
	return out
}

// changeOf extrae la llave cambiada aceptada de un evento de transport ("vieja -> nueva").
func changeOf(e audit.Entry, target string) *HostKeyChange {
	if e.Action != "hostkey.accepted_changed" {
		return nil
	}
	old, nw, ok := strings.Cut(e.Detail, " -> ")
	if !ok {
		return nil
	}
	return &HostKeyChange{Target: target, Old: old, New: nw}
}

func auditor(ctx context.Context, d Deps) func(audit.Entry) {
	return func(e audit.Entry) {
		e.Actor = "patrol"
		d.Audit.Append(ctx, e)
	}
}
