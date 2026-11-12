package assist

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/assist"
	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/platform/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

type target struct {
	host string
	port uint16
	cred string
}

type conn struct {
	sess *transport.Session
	drv  platform.Driver
	plat string // ios o ios-xe, según Detect
}

// devExec implementa assist.Executor con transport y platform. Una conexión por equipo, abierta
// la primera vez que se usa y cerrada con Close. id es el trabajo del guard (plan-X o el runID).
type devExec struct {
	d       service.Deps
	id      string
	targets map[string]target
	policy  transport.HostKeyPolicy
	mu      sync.Mutex
	conns   map[string]*conn
}

func newExec(d service.Deps, id string, targets map[string]target, policy transport.HostKeyPolicy) *devExec {
	return &devExec{d: d, id: id, targets: targets, policy: policy, conns: map[string]*conn{}}
}

func (e *devExec) conn(ctx context.Context, dev string) (*conn, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.conns[dev]; c != nil {
		err := c.drv.Err()
		if err == nil {
			return c, nil
		}
		// La sesión murió (exec-timeout del equipo, corte o un timeout del driver): se abre otra por el guard.
		e.d.Audit("assist.reconnect", dev, fmt.Sprintf("run=%s unusable session: %v", e.id, i18n.English(err)))
		c.close()
		delete(e.conns, dev)
	}
	t, ok := e.targets[dev]
	if !ok {
		return nil, fmt.Errorf("equipo %q desconocido", dev)
	}
	v := e.d.Vault()
	if v == nil {
		return nil, errors.New("la bóveda no existe")
	}
	cred, err := v.Get(t.cred)
	if err != nil {
		return nil, err
	}
	hk := e.d.Hosts().Callback(e.policy, func(en audit.Entry) { e.d.Audit(en.Action, en.Target, en.Detail) })
	sess, err := transport.OpenSSH(ctx, e.d.Guard(), e.id, t.host, t.port, cred, hk, transport.SSHOptions{})
	if err != nil {
		cred.Enable.Destroy()
		return nil, err
	}
	r, w, err := sess.Shell()
	if err != nil {
		cred.Enable.Destroy()
		sess.Close()
		return nil, err
	}
	drv := iosxe.New()
	c := &conn{sess: sess, drv: drv}
	if err := drv.Open(ctx, r, w, cred.Enable); err != nil {
		c.close()
		return nil, err
	}
	// Solo IOS e IOS-XE: las líneas de la lista cerrada son de esa sintaxis.
	p, err := drv.Detect(ctx)
	if err != nil || (p != "ios-xe" && p != "ios") {
		c.close()
		if err == nil {
			err = fmt.Errorf("plataforma %q no soportada por el modo asistido", p)
		}
		return nil, err
	}
	c.plat = p
	e.d.Audit("assist.connect", dev, "run="+e.id)
	e.conns[dev] = c
	return c, nil
}

// Platform dice qué plataforma detectó la sesión de dev ("" si no hay sesión).
func (e *devExec) Platform(dev string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c := e.conns[dev]; c != nil {
		return c.plat
	}
	return ""
}

// SourceAddr es la IP local de la sesión con dev (la que el equipo ve como origen, salvo NAT); vacía si no hay sesión o no se puede leer.
func (e *devExec) SourceAddr(dev string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	c := e.conns[dev]
	if c == nil {
		return ""
	}
	ap, err := netip.ParseAddrPort(c.sess.Client().LocalAddr().String())
	if err != nil {
		return ""
	}
	return ap.Addr().String()
}

func (c *conn) close() { c.drv.Close(); c.sess.Close() }

// Read corre comandos de lectura; cada uno pasa por CheckDenied también aquí.
func (e *devExec) Read(ctx context.Context, dev string, cmds []string) ([]assist.Output, error) {
	for _, cmd := range cmds {
		for _, r := range cmd { // exec-character-bits 7: ver internal/assist.asciiOnly
			if r < 0x20 || r > 0x7e {
				return nil, fmt.Errorf("%w: %q tiene caracteres fuera de ASCII imprimible", playbook.ErrDenied, cmd)
			}
		}
		if err := playbook.CheckDenied("ios-xe", cmd); err != nil {
			return nil, err
		}
	}
	c, err := e.conn(ctx, dev)
	if err != nil {
		return nil, err
	}
	var out []assist.Output
	for _, cmd := range cmds {
		o, err := c.drv.Run(ctx, cmd, 60*time.Second)
		if err != nil {
			return out, err
		}
		out = append(out, assist.Output{Command: cmd, Text: o.Text})
	}
	return out, nil
}

func (e *devExec) Configure(ctx context.Context, dev string, lines []string) ([]assist.Sent, error) {
	c, err := e.conn(ctx, dev)
	if err != nil {
		return nil, err
	}
	res, err := c.drv.Configure(ctx, lines, time.Duration(20+5*len(lines))*time.Second)
	sent := make([]assist.Sent, len(res.Lines))
	for i, l := range res.Lines {
		sent[i] = assist.Sent{Line: l.Line, Output: l.Output, Failed: l.Failed}
	}
	return sent, err
}

// Save solo lo invoca el paso write memory, que el motor pide únicamente si el plan lo incluye y el ingeniero lo confirma.
func (e *devExec) Save(ctx context.Context, dev string) (string, error) {
	c, err := e.conn(ctx, dev)
	if err != nil {
		return "", err
	}
	o, err := c.drv.Run(ctx, "write memory", 60*time.Second)
	if err == nil {
		err = saveErr(o.Text)
	}
	return o.Text, err
}

// saveErr: write memory solo salió bien si el equipo respondió [OK] y ningún error con %
// (p. ej. "%Error opening nvram:/startup-config").
func saveErr(text string) error {
	ok := false
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "%") {
			return fmt.Errorf("el equipo respondió %q", l)
		}
		ok = ok || strings.Contains(l, "[OK]")
	}
	if !ok {
		return errors.New("el equipo no confirmó con [OK]")
	}
	return nil
}

func (e *devExec) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, c := range e.conns {
		c.close()
		delete(e.conns, k)
	}
}
