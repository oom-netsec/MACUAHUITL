package terminal

import (
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// newTelnetCredRig levanta el equipo Telnet de c y guarda en la bóveda la credencial admin/pass; open la usa.
func newTelnetCredRig(t *testing.T, c simulator.Config, pass string) (*rig, *atomic.Int32) {
	t.Helper()
	att := new(atomic.Int32)
	_, f, _, _ := runtime.Caller(0)
	c.Hostname, c.Attempts = "SW1", att
	c.Transcripts = filepath.Join(filepath.Dir(f), "..", "..", "..", "test", "transcripts", "ios-xe")
	if c.Username == "" && !c.TelnetLinePassword {
		c.Username = "admin"
	}
	ap := netip.MustParseAddrPort(simulator.StartTelnet(t, c))
	r := &rig{t: t, d: servicetest.New(t), host: ap.Addr().String(), port: ap.Port()}
	id, err := r.d.CreateVault().Put(vault.Credential{Label: "lab", Username: "admin", Password: secret.New([]byte(pass)), Enable: secret.New([]byte(enableSecret))})
	if err != nil {
		t.Fatal(err)
	}
	r.open = &v1.TerminalOpen{Name: "SW1", Address: r.host, Port: uint32(r.port), CredentialId: id, Protocol: v1.TerminalProtocol_TERMINAL_PROTOCOL_TELNET}
	r.svc = newSvc(r.d)
	r.svc.loginQuiet, r.svc.loginFirst, r.svc.loginNext = 150*time.Millisecond, 3*time.Second, 3*time.Second
	t.Cleanup(r.svc.close)
	return r, att
}

func TestTelnetCredencialEntraSola(t *testing.T) {
	const marca = "MARCA-TELNET-CRED-41"
	logs := capturaLog(t)
	r, att := newTelnetCredRig(t, simulator.Config{Password: marca}, marca)
	st, done, cancel := r.session(r.open)
	defer cancel()
	st.data("tecleado-durante-el-login\r") // se descarta mientras el núcleo contesta el login
	out := st.waitFor(t, "SW1>")
	if !strings.Contains(out, "credencial guardada") {
		t.Errorf("falta el aviso de la credencial en claro: %q", out)
	}
	if att.Load() != 1 {
		t.Errorf("el equipo recibió %d contraseñas, quería 1", att.Load())
	}
	st.data("show version\r")
	st.waitFor(t, "Cisco")
	close(st.in)
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	r.cerrada("terminal.close", "closed by the user")
	if a := r.d.AuditText(); !strings.Contains(a, `credential=`) || !strings.Contains(a, `user=\"admin\" protocol=telnet cleartext=true login=auto`) {
		t.Errorf("auditoría:\n%s", a)
	}
	buscaMarca(t, r, marca, logs.String())
}

// Password de línea (sin usuario) y un banner con «Password:» a media línea: no contesta al banner.
func TestTelnetCredencialPasswordDeLineaYBanner(t *testing.T) {
	const marca = "MARCA-LINEA-55"
	r, att := newTelnetCredRig(t, simulator.Config{Password: marca, TelnetLinePassword: true,
		TelnetBanner: "Aviso. Password: es personal\nNo la compartas\n"}, marca)
	st, done, cancel := r.session(r.open)
	defer cancel()
	st.waitFor(t, "SW1>")
	if att.Load() != 1 {
		t.Errorf("el equipo recibió %d contraseñas, quería 1", att.Load())
	}
	close(st.in)
	wait(t, done)
}

// Contraseña rechazada: se manda una sola vez, avisa y sigue a mano (la sesión no se corta).
func TestTelnetCredencialRechazadaPasaAMano(t *testing.T) {
	r, att := newTelnetCredRig(t, simulator.Config{Password: "pw"}, "MARCA-MALA-08")
	st, done, cancel := r.session(r.open)
	defer cancel()
	out := st.waitFor(t, "a mano")
	if !strings.Contains(out, "rechaz") {
		t.Errorf("aviso = %q", out)
	}
	if att.Load() != 1 {
		t.Fatalf("el equipo recibió %d contraseñas, quería 1 (nunca se reintenta)", att.Load())
	}
	st.data("admin\r")
	st.waitFor(t, "Password: ")
	st.data("pw\r")
	st.waitFor(t, "SW1>")
	close(st.in)
	wait(t, done)
	if a := r.d.AuditText(); !strings.Contains(a, "login=manual") {
		t.Errorf("auditoría sin login=manual:\n%s", a)
	}
}

// Sin pregunta a tiempo: avisa y sigue a mano, sin mandar nada.
func TestTelnetCredencialSinPreguntaPasaAMano(t *testing.T) {
	r, att := newTelnetCredRig(t, simulator.Config{Password: "pw", TelnetLoginDelay: time.Hour}, "pw")
	r.svc.loginFirst = 300 * time.Millisecond
	st, done, cancel := r.session(r.open)
	defer cancel()
	st.waitFor(t, "a mano")
	if att.Load() != 0 {
		t.Errorf("mandó %d contraseñas sin pregunta", att.Load())
	}
	close(st.in)
	wait(t, done)
}

// Una credencial de solo llave no sirve para Telnet: se rechaza sin marcar.
func TestTelnetCredencialDeLlave(t *testing.T) {
	var conns atomic.Int32
	r, _ := newTelnetCredRig(t, simulator.Config{Password: "pw", Conns: &conns}, "pw")
	id, _, err := r.d.V.GenerateKey("pi", "pi")
	if err != nil {
		t.Fatal(err)
	}
	r.open.CredentialId = id
	_, done, cancel := r.session(r.open)
	defer cancel()
	if err := wait(t, done); reason(t, err) != "terminal.err.key_credential" || conns.Load() != 0 {
		t.Fatalf("err = %v, conexiones = %d", err, conns.Load())
	}
	_ = codes.FailedPrecondition
}
