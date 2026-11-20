package terminal

import (
	"google.golang.org/protobuf/proto"
	"net/netip"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// newTelnetRig es newRig sobre el simulador Telnet: sin bóveda ni huellas (Telnet no las usa).
func newTelnetRig(t *testing.T, c simulator.Config) *rig {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	c.Hostname, c.Username, c.Password, c.Enable = "SW1", "admin", "pw", enableSecret
	c.Transcripts = filepath.Join(filepath.Dir(f), "..", "..", "..", "test", "transcripts", "ios-xe")
	ap := netip.MustParseAddrPort(simulator.StartTelnet(t, c))
	r := &rig{t: t, d: servicetest.New(t), host: ap.Addr().String(), port: ap.Port()}
	r.open = &v1.TerminalOpen{Name: "SW1", Address: r.host, Port: uint32(r.port), Protocol: v1.TerminalProtocol_TERMINAL_PROTOCOL_TELNET}
	r.svc = newSvc(r.d)
	t.Cleanup(r.svc.close)
	return r
}

func TestTelnetTecleadoAvisoYAuditoria(t *testing.T) {
	const marca = "MARCA-TELNET-7c1"
	logs := capturaLog(t)
	rec := &simulator.Recorder{}
	r := newTelnetRig(t, simulator.Config{Recorder: rec})
	st, done, cancel := r.session(r.open)
	defer cancel()
	first := <-st.out
	if first.Opened != r.host+":"+strconv.Itoa(int(r.port)) || first.Recording == "" {
		t.Fatalf("primer evento = %+v", first)
	}
	// El aviso llega antes que la salida del equipo.
	if aviso := <-st.out; !strings.Contains(string(aviso.Data), "texto claro") {
		t.Fatalf("segundo evento = %q, quería el aviso", aviso.Data)
	}
	st.waitFor(t, "Username: ")
	st.data("admin\r")
	st.waitFor(t, "Password: ")
	st.data(marca + "\r") // mala: el equipo vuelve a preguntar
	st.waitFor(t, "Username: ")
	st.data("admin\r")
	st.waitFor(t, "Password: ")
	st.data("pw\r")
	st.waitFor(t, "SW1>")
	st.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Resize{Resize: &v1.TerminalSize{Rows: 40, Cols: 120}}}
	st.data("show version\r")
	st.waitFor(t, "Cisco")
	close(st.in)
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
	r.cerrada("terminal.close", "closed by the user")
	a := r.d.AuditText()
	if strings.Count(a, "protocol=telnet cleartext=true") != 2 { // terminal.open y terminal.close
		t.Errorf("auditoría sin protocol=telnet:\n%s", a)
	}
	if !slices.Contains(rec.Lines(), "!naws 120x40") {
		t.Errorf("el resize no llegó por NAWS: %v", rec.Lines())
	}
	buscaMarca(t, r, marca, logs.String()) // lo tecleado en «Password:» no queda en la grabación, la auditoría ni el log
}

// Puerto 0 → 23: el pedido sin puerto marca al 23 (el guard lo ve en su auditoría de la sesión).
func TestTelnetPuertoPorOmision(t *testing.T) {
	r := newTelnetRig(t, simulator.Config{})
	o := r.typedTelnet()
	o.Name, o.Port = "", 0
	o.Address = "127.0.0.1" // nadie escucha en el 23 de loopback en CI: falla al marcar, pero la etiqueta ya dice el puerto
	st, done, cancel := r.session(o)
	defer cancel()
	close(st.in) // si algo escucha en el 23 la sesión se cierra igual: la prueba no se cuelga
	wait(t, done)
	if a := r.d.AuditText(); !strings.Contains(a, `127.0.0.1:23`) {
		t.Fatalf("no marcó al 23:\n%s", a)
	}
}

func (r *rig) typedTelnet() *v1.TerminalOpen {
	return &v1.TerminalOpen{Name: r.open.Name, Address: r.open.Address, Port: r.open.Port, Protocol: r.open.Protocol}
}

// Con Telnet no aplican username, huellas ni host_id (hasta 48-4): se rechazan sin marcar.
func TestTelnetCamposQueNoAplican(t *testing.T) {
	var conns atomic.Int32
	r := newTelnetRig(t, simulator.Config{Conns: &conns})
	for name, mod := range map[string]func(*v1.TerminalOpen){
		"username": func(o *v1.TerminalOpen) { o.Username = "admin" },
		"huella":   func(o *v1.TerminalOpen) { o.AcceptedHostKeyFingerprints = []string{"SHA256:x"} },
		"huella par": func(o *v1.TerminalOpen) {
			o.AcceptedHostKeys = []*v1.AcceptedHostKey{{Host: r.host, Fingerprint: "SHA256:x"}}
		},
	} {
		o := r.typedTelnet()
		mod(o)
		_, done, cancel := r.session(o)
		err := wait(t, done)
		cancel()
		if status.Code(err) != codes.InvalidArgument || reason(t, err) != "terminal.err.telnet_field" {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if !strings.Contains(r.d.AuditText(), `field not valid with telnet: username`) {
		t.Errorf("la auditoría no dice qué campo:\n%s", r.d.AuditText())
	}
	o := &v1.TerminalOpen{HostId: "h1", Protocol: v1.TerminalProtocol_TERMINAL_PROTOCOL_TELNET}
	_, done, cancel := r.session(o)
	defer cancel()
	if err := wait(t, done); status.Code(err) != codes.InvalidArgument {
		t.Errorf("host_id: err = %v", err)
	}
	if conns.Load() != 0 {
		t.Errorf("marcó al equipo %d veces", conns.Load())
	}
}

// Un protocolo que este núcleo no conoce (un cliente más nuevo) se rechaza: no se abre por SSH sin avisar.
func TestTelnetProtocoloDesconocido(t *testing.T) {
	r := newTelnetRig(t, simulator.Config{})
	o := r.typedTelnet()
	o.Protocol = 7
	_, done, cancel := r.session(o)
	defer cancel()
	if err := wait(t, done); status.Code(err) != codes.InvalidArgument || reason(t, err) != "terminal.err.protocol" {
		t.Fatalf("err = %v", err)
	}
}

// TERMINAL_PROTOCOL_SSH explícito abre por SSH como siempre.
func TestSSHExplicito(t *testing.T) {
	r := newRig(t, simulator.Config{})
	o := proto.Clone(r.open).(*v1.TerminalOpen)
	o.Protocol = v1.TerminalProtocol_TERMINAL_PROTOCOL_SSH
	st, done, cancel := r.session(o)
	defer cancel()
	if first := <-st.out; first.Opened != "admin@"+r.host+":"+strconv.Itoa(int(r.port)) {
		t.Fatalf("primer evento = %+v", first)
	}
	st.waitFor(t, "SW1>")
	close(st.in)
	if err := wait(t, done); err != nil {
		t.Fatal(err)
	}
}

// Un equipo sin WILL ECHO: la terminal no repite lo tecleado en «Password:» (no hay eco local).
func TestTelnetSinEcoNoMuestraLaContrasena(t *testing.T) {
	const marca = "MARCA-SIN-ECO-2b"
	r := newTelnetRigPass(t, marca)
	st, done, cancel := r.session(r.open)
	defer cancel()
	st.waitFor(t, "Password: ")
	st.data(marca + "\r")
	if out := st.waitFor(t, "SW1>"); strings.Contains(out, marca) {
		t.Fatalf("la contraseña apareció en la terminal: %q", out)
	}
	close(st.in)
	wait(t, done)
	buscaMarca(t, r, marca, "")
}

func newTelnetRigPass(t *testing.T, pass string) *rig {
	t.Helper()
	ap := netip.MustParseAddrPort(simulator.StartTelnet(t, simulator.Config{Hostname: "SW1", Password: pass, TelnetNoEcho: true, TelnetLinePassword: true}))
	r := &rig{t: t, d: servicetest.New(t), host: ap.Addr().String(), port: ap.Port()}
	r.open = &v1.TerminalOpen{Name: "SW1", Address: r.host, Port: uint32(r.port), Protocol: v1.TerminalProtocol_TERMINAL_PROTOCOL_TELNET}
	r.svc = newSvc(r.d)
	t.Cleanup(r.svc.close)
	return r
}

// Revisión de 48-3: si el cliente se va a media salida larga, no quedan goroutines. La carrera exacta (el canal hacia el
// repartidor lleno justo cuando éste sale) no se reproduce de forma determinista; esto cubre el camino de cierre.
func TestClienteSeVaAMediaSalidaNoDejaGoroutines(t *testing.T) {
	r := newRig(t, simulator.Config{StreamCommand: "show tech", StreamLines: 5000})
	base := runtime.NumGoroutine()
	st, done, cancel := r.session(r.open)
	st.waitFor(t, "SW1>")
	st.data("show tech\r")
	st.waitFor(t, "linea 1 de")
	cancel() // el cliente se va: Send falla con la salida todavía llegando
	wait(t, done)
	if !goroutinesAt(base) {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines %d > base %d\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
	}
}
