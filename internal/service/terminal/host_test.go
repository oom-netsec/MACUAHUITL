package terminal

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const startup = "cmd /c echo macuahuitl-ok"

// pwSecreto no puede aparecer por azar en una huella base64 de la auditoría (con «pw» pasaba ~1 % de las veces).
const pwSecreto = "s3creto-no-sale"

// hrig es un host linux/windows simulado que solo acepta publickey y contesta exec.
type hrig struct {
	*rig
	keyID, pwID string
	conns       atomic.Int32
	log         *[]string
	logMu       sync.Mutex
	rec         *simulator.Recorder
	terms       []string
	hk          string
}

func newHRig(t *testing.T) *hrig {
	t.Helper()
	h := &hrig{log: new([]string), rec: &simulator.Recorder{}}
	r := newRig(t, simulator.Config{})
	h.rig = r
	id, pub, err := r.d.V.GenerateKey("pi", "pi")
	if err != nil {
		t.Fatal(err)
	}
	h.keyID = id
	if h.pwID, err = r.d.V.Put(vault.Credential{Label: "clave", Username: "admin", Password: secret.New([]byte(pwSecreto))}); err != nil {
		t.Fatal(err)
	}
	_, f, _, _ := runtime.Caller(0)
	addr, hk := simulator.Start(t, simulator.Config{Hostname: "pi", Username: "pi", Password: "x", NoPassword: true,
		Transcripts:    filepath.Join(filepath.Dir(f), "..", "..", "..", "test", "transcripts", "ios-xe"),
		AuthorizedKeys: simulator.Keys(simulator.ParseAuthorizedKey(t, pub.AuthorizedKey())), AuthLog: h.log, Recorder: h.rec, Conns: &h.conns,
		Exec: func(cmd string) string { return "salida:" + cmd + "\n" },
		OnPty: func(term string) {
			h.logMu.Lock()
			h.terms = append(h.terms, term)
			h.logMu.Unlock()
		}})
	ap := netip.MustParseAddrPort(addr)
	r.host, r.port = ap.Addr().String(), ap.Port()
	h.hk = transport.Fingerprint(hk)
	return h
}

func (h *hrig) addHost(id, platform, address, credID, cmd string) {
	h.t.Helper()
	_, err := h.d.DB().Exec(`INSERT INTO hosts(id,name,address,port,platform,folder,tags_json,credential_id,notes,startup_command,created_at,updated_at)
		VALUES(?,?,?,?,?,'','[]',?,'',?,'t','t')`, id, id, address, h.port, platform, credID, cmd)
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *hrig) open(hostID, expected string, accepted bool) *v1.TerminalOpen {
	o := &v1.TerminalOpen{HostId: hostID, ExpectedStartupCommand: expected}
	if accepted {
		o.AcceptedHostKeyFingerprints = []string{h.hk}
	}
	return o
}

func reason(t *testing.T, err error) string {
	t.Helper()
	for _, d := range status.Convert(err).Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return ei.Reason
		}
	}
	return ""
}

// nada comprueba que el rechazo no tocó el simulador (ni un Dial sin handshake) ni abrió sesión.
func (h *hrig) nada(err error, code codes.Code, why string) {
	h.t.Helper()
	if status.Code(err) != code || reason(h.t, err) != why {
		h.t.Fatalf("err = %v (%s), quería %v %s", err, reason(h.t, err), code, why)
	}
	if n := h.conns.Load(); n != 0 {
		h.t.Fatalf("%d conexiones al simulador", n)
	}
	if a := h.d.AuditText(); strings.Contains(a, `"action":"terminal.open"`) {
		h.t.Fatalf("se auditó una apertura:\n%s", a)
	}
}

func TestHostConOrdenCorreExecConPty(t *testing.T) {
	h := newHRig(t)
	h.addHost("h1", "windows", h.host, h.keyID, startup)
	st, done, cancel := h.session(h.open("h1", startup, true))
	defer cancel()
	st.waitFor(t, "salida:"+startup)
	if err := wait(t, done); err != nil { // la orden terminó: la sesión cierra sola, sin error
		t.Fatalf("err = %v", err)
	}
	if l := h.rec.Lines(); len(l) != 1 || l[0] != "!exec pty=true "+startup {
		t.Fatalf("recorder %v", l)
	}
	if len(h.terms) != 1 || h.terms[0] != "xterm-256color" {
		t.Fatalf("term %v", h.terms)
	}
	h.logMu.Lock()
	for _, m := range *h.log {
		if m != "none" && m != "publickey" {
			t.Fatalf("método %q (%v)", m, *h.log)
		}
	}
	h.logMu.Unlock()
	a := h.d.AuditText()
	if !strings.Contains(a, `host=h1`) || !strings.Contains(a, `startup=\"cmd /c echo macuahuitl-ok\"`) {
		t.Fatalf("falta host=/startup= en la auditoría:\n%s", a)
	}
	for _, s := range []string{"PRIVATE KEY", pwSecreto} {
		if strings.Contains(a, s) {
			t.Fatalf("la auditoría trae %q:\n%s", s, a)
		}
	}
	_, rec := h.cerrada("terminal.close", "the device closed the session")
	b, err := os.ReadFile(rec)
	if err != nil || !strings.Contains(string(b), "orden de inicio: "+strconv.Quote(startup)) {
		t.Fatalf("la grabación no marca la orden (%v):\n%s", err, b)
	}
}

func TestHostSinOrdenAbreShellConXterm(t *testing.T) {
	h := newHRig(t)
	h.addHost("h1", "linux", h.host, h.keyID, "")
	st, _, cancel := h.session(h.open("h1", "", true))
	defer cancel()
	st.waitFor(t, "pi>")
	if l := h.rec.Lines(); len(l) != 0 {
		t.Fatalf("hubo exec: %v", l)
	}
	if len(h.terms) != 1 || h.terms[0] != "xterm-256color" {
		t.Fatalf("term %v", h.terms)
	}
	if !strings.Contains(h.d.AuditText(), `startup=none`) {
		t.Fatalf("falta startup=none:\n%s", h.d.AuditText())
	}
}

func TestHostPrimeraVezPideHuellaConKeyType(t *testing.T) {
	h := newHRig(t)
	h.addHost("h1", "linux", h.host, h.keyID, startup)
	_, done, cancel := h.session(h.open("h1", startup, false))
	defer cancel()
	err := wait(t, done)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
	var meta map[string]string
	for _, d := range status.Convert(err).Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			meta = ei.Metadata
		}
	}
	if meta["key_type"] != "ssh-ed25519" || !strings.HasPrefix(meta["fingerprint"], "SHA256:") {
		t.Fatalf("metadata %v", meta)
	}
	st, done2, cancel2 := h.session(h.open("h1", startup, true)) // con la huella aceptada conecta
	defer cancel2()
	st.waitFor(t, "salida:"+startup)
	wait(t, done2)
}

func TestExpectedDistintoNoConecta(t *testing.T) {
	h := newHRig(t)
	h.addHost("h1", "linux", "no-existe.invalid", h.keyID, startup) // si llegara a Guard.Allow sería PermissionDenied por el DNS
	for _, exp := range []string{"cmd /c echo otro", "", startup + " "} {
		_, done, cancel := h.session(h.open("h1", exp, true))
		err := wait(t, done)
		cancel()
		h.nada(err, codes.FailedPrecondition, "terminal.err.startup_changed")
	}
	if !strings.Contains(h.d.AuditText(), `startup changed`) {
		t.Fatalf("falta el motivo en la auditoría:\n%s", h.d.AuditText())
	}
}

func TestHostIDEsExclusivo(t *testing.T) {
	h := newHRig(t)
	h.addHost("h1", "linux", h.host, h.keyID, "")
	for nombre, o := range map[string]*v1.TerminalOpen{
		"address":       {HostId: "h1", Address: h.host},
		"port":          {HostId: "h1", Port: 22},
		"credential_id": {HostId: "h1", CredentialId: h.keyID},
	} {
		t.Run(nombre, func(t *testing.T) {
			_, done, cancel := h.session(o)
			err := wait(t, done)
			cancel()
			h.nada(err, codes.InvalidArgument, "terminal.err.host_and_address")
		})
	}
}

func TestCredencialKeyConDireccionAMano(t *testing.T) {
	h := newHRig(t)
	_, done, cancel := h.session(&v1.TerminalOpen{Address: "no-existe.invalid", Port: 22, CredentialId: h.keyID}) // antes de Guard.Allow: no resuelve DNS
	err := wait(t, done)
	cancel()
	h.nada(err, codes.FailedPrecondition, "terminal.err.key_credential")
}

func TestHostCiscoConCredencialKey(t *testing.T) {
	h := newHRig(t)
	for i, p := range []string{"ios-xe", ""} {
		h.addHost("c-"+p+"x", p, "no-existe"+strconv.Itoa(i)+".invalid", h.keyID, "")
		_, done, cancel := h.session(h.open("c-"+p+"x", "", true))
		err := wait(t, done)
		cancel()
		h.nada(err, codes.FailedPrecondition, "terminal.err.key_credential")
	}
	// con la bóveda cerrada no se puede saber el tipo de la credencial: se pide abrirla, sin conectar
	h.d.V.LockAll()
	_, done, cancel := h.session(h.open("c-ios-xex", "", true))
	err := wait(t, done)
	cancel()
	h.nada(err, codes.FailedPrecondition, "terminal.err.vault_closed")
}

func TestHostCiscoConPasswordSigueIgual(t *testing.T) {
	h := newHRig(t)
	// un Cisco por host_id con credencial de contraseña no es genérico: vt100 y shell, como hoy
	h.addHost("c1", "ios-xe", h.host, h.pwID, "")
	_, done, cancel := h.session(h.open("c1", "", true))
	defer cancel()
	err := wait(t, done)
	if status.Code(err) != codes.PermissionDenied { // el simulador de este rig solo acepta llaves: llega a conectar y falla la autenticación
		t.Fatalf("err = %v", err)
	}
	if h.conns.Load() == 0 {
		t.Fatal("no conectó")
	}
}

func TestHostSinCredencialOInexistente(t *testing.T) {
	h := newHRig(t)
	h.addHost("h1", "linux", h.host, "", "")
	_, done, cancel := h.session(h.open("h1", "", true))
	err := wait(t, done)
	cancel()
	h.nada(err, codes.FailedPrecondition, "terminal.err.host_no_credential")
	_, done, cancel = h.session(h.open("nada", "", true))
	err = wait(t, done)
	cancel()
	h.nada(err, codes.NotFound, "terminal.err.host_not_found")
}

// Un Cisco con contraseña, por host_id o con la dirección a mano, sigue como hoy: shell con vt100 y sin exec.
func TestCiscoConPasswordShellVt100(t *testing.T) {
	var mu sync.Mutex
	var terms []string
	rec := &simulator.Recorder{}
	r := newRig(t, simulator.Config{Recorder: rec, OnPty: func(term string) { mu.Lock(); terms = append(terms, term); mu.Unlock() }})
	if _, err := r.d.DB().Exec(`INSERT INTO hosts(id,name,address,port,platform,folder,tags_json,credential_id,notes,startup_command,created_at,updated_at)
		VALUES('c1','c1',?,?,'ios-xe','','[]',?,'','','t','t')`, r.host, r.port, r.open.CredentialId); err != nil {
		t.Fatal(err)
	}
	for nombre, o := range map[string]*v1.TerminalOpen{
		"host_id":   {HostId: "c1", AcceptedHostKeyFingerprints: r.open.AcceptedHostKeyFingerprints},
		"dirección": r.open,
	} {
		st, done, cancel := r.session(o)
		st.waitFor(t, "SW1")
		cancel()
		wait(t, done)
		mu.Lock()
		got := append([]string(nil), terms...)
		terms = nil
		mu.Unlock()
		if len(got) != 1 || got[0] != "vt100" {
			t.Fatalf("%s: term %v", nombre, got)
		}
		for _, l := range rec.Lines() {
			if strings.HasPrefix(l, "!exec") {
				t.Fatalf("%s: corrió exec: %v", nombre, rec.Lines())
			}
		}
	}
}

// Una orden guardada en un host que no es linux/windows (Clean no lo deja: base alterada o vieja) no se anota ni se abre.
func TestOrdenEnHostNoGenericoSeRechaza(t *testing.T) {
	h := newHRig(t)
	h.addHost("c2", "ios-xe", "no-existe.invalid", h.pwID, "show version")
	_, done, cancel := h.session(h.open("c2", "show version", true))
	err := wait(t, done)
	cancel()
	h.nada(err, codes.FailedPrecondition, "terminal.err.startup_changed")
}
