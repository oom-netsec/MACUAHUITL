package terminal

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// fakeStream hace de cliente y de servidor del stream en la misma prueba.
type fakeStream struct {
	v1.TerminalService_OpenTerminalServer
	ctx context.Context
	in  chan *v1.OpenTerminalRequest
	out chan *v1.OpenTerminalResponse
}

func newStream(ctx context.Context) *fakeStream {
	return &fakeStream{ctx: ctx, in: make(chan *v1.OpenTerminalRequest, 64), out: make(chan *v1.OpenTerminalResponse, 256)}
}
func (f *fakeStream) Context() context.Context { return f.ctx }
func (f *fakeStream) Send(r *v1.OpenTerminalResponse) error {
	select {
	case f.out <- r:
		return nil
	case <-f.ctx.Done():
		return f.ctx.Err()
	}
}
func (f *fakeStream) Recv() (*v1.OpenTerminalRequest, error) {
	select {
	case m, ok := <-f.in:
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	}
}
func (f *fakeStream) data(s string) {
	f.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Data{Data: []byte(s)}}
}

// waitFor lee lo que devuelve el equipo hasta que aparece want.
func (f *fakeStream) waitFor(t *testing.T, want string) string {
	t.Helper()
	var got strings.Builder
	deadline := time.After(10 * time.Second)
	for {
		select {
		case r := <-f.out:
			got.Write(r.Data)
			if strings.Contains(got.String(), want) {
				return got.String()
			}
		case <-deadline:
			t.Fatalf("no llegó %q; salida: %q", want, got.String())
		}
	}
}

type rig struct {
	t    *testing.T
	svc  *termSvc
	d    *servicetest.Deps
	open *v1.TerminalOpen
	host string
	port uint16
}

const enableSecret = "MARKER-EN-SECRETO"

func newRig(t *testing.T, c simulator.Config) *rig {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	d := servicetest.New(t)
	v := d.CreateVault()
	id, err := v.Put(vault.Credential{Label: "lab", Username: "admin", Password: secret.New([]byte("pw")), Enable: secret.New([]byte(enableSecret))})
	if err != nil {
		t.Fatal(err)
	}
	c.Hostname, c.Username, c.Password, c.Enable = "SW1", "admin", "pw", enableSecret
	c.Transcripts = filepath.Join(filepath.Dir(f), "..", "..", "..", "test", "transcripts", "ios-xe")
	addr, hk := simulator.Start(t, c)
	ap := netip.MustParseAddrPort(addr)
	r := &rig{t: t, d: d, host: ap.Addr().String(), port: ap.Port()}
	r.open = &v1.TerminalOpen{Name: "SW1", Address: r.host, Port: uint32(r.port), CredentialId: id, AcceptedHostKeyFingerprints: []string{transport.Fingerprint(hk)}}
	r.svc = newSvc(d)
	t.Cleanup(r.svc.close)
	return r
}

// session abre la terminal en segundo plano. done recibe el resultado del manejador.
func (r *rig) session(open *v1.TerminalOpen) (*fakeStream, chan error, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	st := newStream(ctx)
	st.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: open}}
	done := make(chan error, 1)
	go func() { done <- r.svc.OpenTerminal(st) }()
	return st, done, cancel
}

func wait(t *testing.T, done chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("el manejador no terminó")
		return nil
	}
}

var sessionRe = regexp.MustCompile(`sesion=(term-[0-9a-f]+)`)

// cerrada comprueba lo que toda salida debe dejar: auditoría de cierre y el guard sin autorización.
func (r *rig) cerrada(wantAction, wantReason string) (id, recording string) {
	r.t.Helper()
	a := r.d.AuditText()
	m := sessionRe.FindStringSubmatch(a)
	if m == nil {
		r.t.Fatalf("la auditoría no trae la sesión:\n%s", a)
	}
	id = m[1]
	if !strings.Contains(a, `"action":"`+wantAction+`"`) || !strings.Contains(a, "guard=revocado") || !strings.Contains(a, wantReason) {
		r.t.Fatalf("falta %s / %q / guard=revocado:\n%s", wantAction, wantReason, a)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c, err := r.d.Guard().Dial(ctx, id, r.host, r.port); !errors.Is(err, transport.ErrEgressDenied) {
		if c != nil {
			c.Close()
		}
		r.t.Fatalf("el guard sigue autorizando la sesión %s: %v", id, err)
	}
	if m := regexp.MustCompile(`grabacion=(\S+)`).FindStringSubmatch(a); m != nil {
		recording = strings.Trim(m[1], `"\`)
	}
	return id, recording
}

func TestElClienteCierraLaPestana(t *testing.T) {
	r := newRig(t, simulator.Config{})
	st, done, cancel := r.session(r.open)
	defer cancel()
	first := <-st.out
	if first.Opened != "admin@"+r.host+":"+strconv.Itoa(int(r.port)) || first.Recording == "" {
		t.Fatalf("primer evento = %+v", first)
	}
	st.waitFor(t, "SW1>")
	st.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Resize{Resize: &v1.TerminalSize{Rows: 40, Cols: 120}}}
	st.data("show version\r")
	st.waitFor(t, "Cisco")
	close(st.in) // cerrar el envío, como al cerrar la pestaña
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	_, rec := r.cerrada("terminal.close", "cerrada por el usuario")
	b, err := os.ReadFile(rec)
	if err != nil || !strings.Contains(string(b), ">>> show version") || !strings.Contains(string(b), "Cisco") || !strings.Contains(string(b), "### cerrado") {
		t.Fatalf("grabación %v:\n%s", err, b)
	}
	if fi, _ := os.Stat(rec); fi.Mode().Perm() != 0o600 {
		t.Errorf("grabación = %v", fi.Mode().Perm())
	}
	a := r.d.AuditText()
	if !strings.Contains(a, `"action":"terminal.open"`) || !strings.Contains(a, "manual=true") || strings.Contains(a, "show version") {
		t.Errorf("auditoría de apertura:\n%s", a)
	}
}

// Punto delicado: el secreto tecleado en el prompt Password: no se graba (ni en el archivo ni en la auditoría).
func TestNoGrabaLaContrasenaDelPrompt(t *testing.T) {
	r := newRig(t, simulator.Config{})
	st, done, cancel := r.session(r.open)
	defer cancel()
	st.waitFor(t, "SW1>")
	st.data("enable\r")
	st.waitFor(t, "Password:")
	for _, c := range enableSecret { // tecla por tecla, como la UI
		st.data(string(c))
	}
	st.data("\r")
	st.waitFor(t, "SW1#")
	st.data("show version\r")
	st.waitFor(t, "Cisco")
	close(st.in)
	wait(t, done)
	_, rec := r.cerrada("terminal.close", "cerrada por el usuario")
	b, _ := os.ReadFile(rec)
	if strings.Contains(string(b), enableSecret) || strings.Contains(r.d.AuditText(), enableSecret) {
		t.Fatalf("el secreto quedó grabado:\n%s", b)
	}
	if !strings.Contains(string(b), ">>> [oculto]") || !strings.Contains(string(b), ">>> enable") || !strings.Contains(string(b), ">>> show version") {
		t.Errorf("grabación:\n%s", b)
	}
}

func TestCierreDelNucleoConUnaSesionViva(t *testing.T) {
	r := newRig(t, simulator.Config{})
	st, done, cancel := r.session(r.open)
	defer cancel()
	st.waitFor(t, "SW1>")
	r.d.CloseAll() // lo que hace el núcleo al cerrarse: corre lo registrado con OnClose
	r.svc.close()
	if err := wait(t, done); status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v", err)
	}
	r.cerrada("terminal.close", "núcleo cerrándose")
	if err := r.svc.OpenTerminal(func() *fakeStream {
		s := newStream(context.Background())
		s.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: r.open}}
		return s
	}()); status.Code(err) != codes.Unavailable {
		t.Errorf("tras cerrar no abre sesiones: %v", err)
	}
}

func TestElEquipoCortaLaSesion(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  simulator.Config
		act  func(*fakeStream, context.CancelFunc)
		want string
	}{
		"exit":         {simulator.Config{}, func(st *fakeStream, _ context.CancelFunc) { st.data("exit\r") }, "el equipo cerró la sesión"},
		"exec-timeout": {simulator.Config{IdleTimeout: 300 * time.Millisecond}, func(*fakeStream, context.CancelFunc) {}, "el equipo cerró la sesión"},
		"cliente-cae":  {simulator.Config{}, func(_ *fakeStream, cancel context.CancelFunc) { cancel() }, "cliente desconectado"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, tc.cfg)
			st, done, cancel := r.session(r.open)
			defer cancel()
			st.waitFor(t, "SW1>")
			tc.act(st, cancel)
			if err := wait(t, done); err != nil && name != "cliente-cae" {
				t.Fatalf("err = %v", err)
			}
			r.cerrada("terminal.close", tc.want)
		})
	}
}

func TestFallosAlAbrirRevocanYAuditan(t *testing.T) {
	// Bóveda cerrada: ni se autoriza el guard.
	r := newRig(t, simulator.Config{})
	r.d.V.LockAll()
	_, done0, cancel0 := r.session(r.open)
	defer cancel0()
	if err := wait(t, done0); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("bóveda cerrada: %v", err)
	}
	// Llave de host nueva sin aceptar.
	r2 := newRig(t, simulator.Config{})
	o := &v1.TerminalOpen{Name: "SW1", Address: r2.host, Port: uint32(r2.port), CredentialId: r2.open.CredentialId}
	_, done, cancel := r2.session(o)
	defer cancel()
	if err := wait(t, done); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "SHA256:") {
		t.Fatalf("llave nueva: %v", err)
	}
	r2.cerrada("terminal.failed", "llave de host")
}

func TestPrimerMensajeDebeAbrir(t *testing.T) {
	r := newRig(t, simulator.Config{})
	st := newStream(context.Background())
	st.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Data{Data: []byte("x")}}
	if err := r.svc.OpenTerminal(st); status.Code(err) != codes.InvalidArgument {
		t.Errorf("%v", err)
	}
	st = newStream(context.Background())
	st.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: &v1.TerminalOpen{}}}
	if err := r.svc.OpenTerminal(st); status.Code(err) != codes.InvalidArgument {
		t.Errorf("sin equipo: %v", err)
	}
}

// Un rechazo antes de abrir (bóveda cerrada, límite de sesiones, el guard no autoriza) también se audita.
func TestRechazosAlAbrirQuedanAuditados(t *testing.T) {
	casos := map[string]struct {
		prep   func(r *rig)
		open   func(r *rig) *v1.TerminalOpen
		code   codes.Code
		reason string
	}{
		"bóveda cerrada": {func(r *rig) { r.d.V.LockAll() }, func(r *rig) *v1.TerminalOpen { return r.open }, codes.FailedPrecondition, "bóveda"},
		"límite":         {func(r *rig) { r.svc.live.Store(maxSessions) }, func(r *rig) *v1.TerminalOpen { return r.open }, codes.ResourceExhausted, "máximo"},
		"guard": {func(*rig) {}, func(r *rig) *v1.TerminalOpen {
			return &v1.TerminalOpen{Name: "X", Address: "10.0.0.1/8", Port: 22, CredentialId: r.open.CredentialId}
		}, codes.PermissionDenied, "bits de host"},
	}
	for nombre, c := range casos {
		r := newRig(t, simulator.Config{})
		c.prep(r)
		_, done, cancel := r.session(c.open(r))
		if err := wait(t, done); status.Code(err) != c.code {
			t.Errorf("%s: %v", nombre, err)
		}
		cancel()
		if a := r.d.AuditText(); !strings.Contains(a, `"action":"terminal.failed"`) || !strings.Contains(a, c.reason) {
			t.Errorf("%s: sin terminal.failed con el motivo:\n%s", nombre, a)
		}
	}
}
