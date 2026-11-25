package terminal

import (
	"net/netip"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
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
}

// Revisión de 48-3: un AAA lento (el equipo calla tras la contraseña) no se da por entrada; el rechazo que llega
// después se ve, se avisa y se audita.
func TestTelnetCredencialRechazoLento(t *testing.T) {
	r, att := newTelnetCredRig(t, simulator.Config{Password: "pw", TelnetVerdictDelay: 800 * time.Millisecond}, "MARCA-MALA-LENTA")
	st, done, cancel := r.session(r.open)
	defer cancel()
	if out := st.waitFor(t, "a mano"); !strings.Contains(out, "rechaz") {
		t.Errorf("aviso = %q", out)
	}
	if att.Load() != 1 {
		t.Fatalf("el equipo recibió %d contraseñas, quería 1", att.Load())
	}
	close(st.in)
	wait(t, done)
	if a := r.d.AuditText(); !strings.Contains(a, "login=manual") {
		t.Errorf("auditoría sin login=manual:\n%s", a)
	}
}

// Sin veredicto antes de cerrar (el equipo sigue callado): la auditoría dice que se mandó, no que entró.
func TestTelnetCredencialSinVeredicto(t *testing.T) {
	r, _ := newTelnetCredRig(t, simulator.Config{Password: "pw", TelnetVerdictDelay: time.Hour}, "pw")
	st, done, cancel := r.session(r.open)
	defer cancel()
	st.waitFor(t, "Password: ")
	time.Sleep(600 * time.Millisecond) // varias veces loginQuiet: si diera «auto» por silencio, ya lo habría hecho
	close(st.in)
	wait(t, done)
	if a := r.d.AuditText(); !strings.Contains(a, "login=sent") {
		t.Errorf("auditoría sin login=sent:\n%s", a)
	}
}

// Una credencial sin contraseña no gasta un intento con una respuesta vacía: pasa a mano sin mandar nada.
func TestTelnetCredencialSinContrasena(t *testing.T) {
	r, att := newTelnetCredRig(t, simulator.Config{Password: "pw"}, "")
	st, done, cancel := r.session(r.open)
	defer cancel()
	st.waitFor(t, "a mano")
	if att.Load() != 0 {
		t.Errorf("mandó %d contraseñas vacías", att.Load())
	}
	close(st.in)
	wait(t, done)
}

// Fase 48-4: un host Telnet de la libreta abre por Telnet con su protocolo y puerto; con credencial, el núcleo contesta
// el login; sin credencial, se teclea. El pedido no trae protocolo (lo pone el host).
func TestTelnetPorHostDeLaLibreta(t *testing.T) {
	for _, conCred := range []bool{true, false} {
		r, att := newTelnetCredRig(t, simulator.Config{Password: "pw"}, "pw")
		cred := ""
		if conCred {
			cred = r.open.CredentialId
		}
		if _, err := r.d.DB().Exec(`INSERT INTO hosts(id,name,address,port,platform,folder,tags_json,credential_id,notes,startup_command,created_at,updated_at,protocol)
			VALUES('h1','viejo',?,?,'ios','','[]',?,'','','t','t','telnet')`, r.host, r.port, cred); err != nil {
			t.Fatal(err)
		}
		st, done, cancel := r.session(&v1.TerminalOpen{HostId: "h1"})
		if first := <-st.out; first.Opened != r.host+":"+strconv.Itoa(int(r.port)) || first.Protocol != v1.TerminalProtocol_TERMINAL_PROTOCOL_TELNET {
			t.Fatalf("primer evento = %+v", first)
		}
		if !conCred {
			st.waitFor(t, "Username: ")
			st.data("admin\r")
			st.waitFor(t, "Password: ")
			st.data("pw\r")
		}
		st.waitFor(t, "SW1>")
		if att.Load() != 1 {
			t.Errorf("con credencial %v: %d contraseñas", conCred, att.Load())
		}
		close(st.in)
		if err := wait(t, done); err != nil {
			t.Fatal(err)
		}
		cancel()
		if a := r.d.AuditText(); !strings.Contains(a, "protocol=telnet") || !strings.Contains(a, "host=h1") {
			t.Errorf("auditoría:\n%s", a)
		}
	}
}

// Con host_id el protocolo lo pone el host: un pedido que además trae protocolo se rechaza sin marcar.
func TestHostConProtocoloEnElPedido(t *testing.T) {
	r, _ := newTelnetCredRig(t, simulator.Config{Password: "pw"}, "pw")
	if _, err := r.d.DB().Exec(`INSERT INTO hosts(id,name,address,port,platform,folder,tags_json,credential_id,notes,startup_command,created_at,updated_at,protocol)
		VALUES('h1','viejo',?,?,'ios','','[]','','','','t','t','telnet')`, r.host, r.port); err != nil {
		t.Fatal(err)
	}
	_, done, cancel := r.session(&v1.TerminalOpen{HostId: "h1", Protocol: v1.TerminalProtocol_TERMINAL_PROTOCOL_TELNET})
	defer cancel()
	if err := wait(t, done); reason(t, err) != "terminal.err.host_and_address" {
		t.Fatalf("err = %v", err)
	}
}

// Revisión de 48-4: datos de la libreta alterados o fuera de regla en un host telnet se rechazan sin marcar (y sin
// tumbar el núcleo: con orden de inicio, el camino de SSH genérico no se toma con una sesión Telnet).
func TestHostTelnetDatosQueNoAplican(t *testing.T) {
	var conns atomic.Int32
	r, _ := newTelnetCredRig(t, simulator.Config{Password: "pw", Conns: &conns}, "pw")
	keyID, _, err := r.d.V.GenerateKey("k", "k")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	ins := func(id, platform, cred, startup string) {
		n++
		if _, err := r.d.DB().Exec(`INSERT INTO hosts(id,name,address,port,platform,folder,tags_json,credential_id,notes,startup_command,created_at,updated_at,protocol)
			VALUES(?,?,?,?,?,'','[]',?,'',?,'t','t','telnet')`, id, id, r.host, int(r.port)+n, platform, cred, startup); err != nil {
			t.Fatal(err)
		}
	}
	ins("orden", "linux", "", "tmux")
	ins("llave", "linux", keyID, "")
	ins("sin", "ios", "", "")
	for _, c := range []struct {
		o      *v1.TerminalOpen
		reason string
	}{
		{&v1.TerminalOpen{HostId: "orden", ExpectedStartupCommand: "tmux"}, "terminal.err.startup_changed"},
		{&v1.TerminalOpen{HostId: "llave"}, "terminal.err.key_credential"},
		{&v1.TerminalOpen{HostId: "sin", Username: "admin"}, "terminal.err.telnet_field"},
		{&v1.TerminalOpen{HostId: "sin", AcceptedHostKeyFingerprints: []string{"SHA256:x"}}, "terminal.err.telnet_field"},
	} {
		_, done, cancel := r.session(c.o)
		err := wait(t, done)
		cancel()
		if reason(t, err) != c.reason {
			t.Errorf("%s: err = %v, quería %s", c.o.HostId, err, c.reason)
		}
	}
	if conns.Load() != 0 {
		t.Errorf("marcó al equipo %d veces", conns.Load())
	}
}

// El login avisa (onSecret) justo antes de mandar la contraseña, para que la grabación tape su eco si el equipo la
// devuelve; nunca antes de que se pida.
func TestTelnetLoginAvisaAntesDeLaContraseña(t *testing.T) {
	var w strings.Builder
	l := newTelnetLogin("admin", secret.New([]byte("Cl4ve")), &w, time.Hour, time.Hour, time.Hour)
	enviado := ""
	l.onSecret = func() { enviado = w.String() }
	l.output([]byte("Username: "))
	l.stable()
	if enviado != "" {
		t.Fatalf("avisó al mandar el usuario: %q", enviado)
	}
	l.output([]byte("admin\r\nPassword: "))
	l.stable()
	if enviado != "admin\r" || !strings.HasSuffix(w.String(), "Cl4ve\r") {
		t.Fatalf("aviso con %q enviado; total %q", enviado, w.String())
	}
}
