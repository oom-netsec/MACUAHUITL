package transport

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// abrirTelnet levanta el simulador Telnet con c, autoriza su dirección en el guard y abre la sesión.
func abrirTelnet(t *testing.T, c simulator.Config) (*TelnetSession, *bufio.Reader, io.Writer) {
	t.Helper()
	ap := netip.MustParseAddrPort(simulator.StartTelnet(t, c))
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{ap.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	s, err := OpenTelnet(context.Background(), g, "j", ap.Addr().String(), ap.Port(), TelnetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	r, w, err := s.ShellSize("vt100", 24, 200)
	if err != nil {
		t.Fatal(err)
	}
	return s, bufio.NewReader(r), w
}

// leeHasta lee lo que el equipo manda (ya sin la capa Telnet) hasta suffix.
func leeHasta(t *testing.T, r *bufio.Reader, suffix string) string {
	t.Helper()
	got := make(chan string, 1)
	go func() {
		var b strings.Builder
		for !strings.HasSuffix(b.String(), suffix) {
			c, err := r.ReadByte()
			if err != nil {
				break
			}
			b.WriteByte(c)
		}
		got <- b.String()
	}()
	select {
	case s := <-got:
		if !strings.HasSuffix(s, suffix) {
			t.Fatalf("esperaba %q, llegó %q", suffix, s)
		}
		return s
	case <-time.After(5 * time.Second):
		t.Fatalf("no llegó %q", suffix)
	}
	return ""
}

func TestTelnetLoginComandoYNegociacion(t *testing.T) {
	rec := &simulator.Recorder{}
	cfg := simulator.Config{Hostname: "SW1", Username: "admin", Password: "pw", Recorder: rec,
		Commands: map[string]string{"show ff": "a\xffb\rc\n"}, TelnetUnknownOption: true}
	s, r, w := abrirTelnet(t, cfg)
	leeHasta(t, r, "Username: ")
	io.WriteString(w, "admin\r")
	leeHasta(t, r, "Password: ")
	io.WriteString(w, "pw\r")
	leeHasta(t, r, "SW1>")
	// Sin capa Telnet en la salida: 0xFF llega como un solo byte y el CR NUL del equipo como CR.
	io.WriteString(w, "show ff\r")
	if out := leeHasta(t, r, "SW1>"); !strings.Contains(out, "a\xffb\rc") || strings.Contains(out, "\x00") {
		t.Fatalf("salida = %q", out)
	}
	// Resize manda NAWS (RFC 1073); 255 columnas viajan como IAC IAC dentro del SB.
	if err := s.Resize(40, 255); err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, "\r")
	leeHasta(t, r, "SW1>")
	lines := rec.Lines()
	for _, l := range []string{"!naws 200x24", "!naws 255x40", "!ttype VT100", "!neg DO 1", "!neg DO 3", "!neg WILL 31", "!neg WILL 24", "!neg DONT 200"} {
		if !slices.Contains(lines, l) {
			t.Errorf("falta %q en lo que mandó el cliente: %v", l, lines)
		}
	}
}

// Sin WILL ECHO del equipo, el cliente no repite nada: lo tecleado en «Password:» no aparece en la salida.
func TestTelnetSinEcoNoRepiteLaContrasena(t *testing.T) {
	_, r, w := abrirTelnet(t, simulator.Config{Hostname: "SW1", Password: "MARCA-PW", TelnetLinePassword: true, TelnetNoEcho: true})
	leeHasta(t, r, "Password: ")
	io.WriteString(w, "MARCA-PW\r")
	if out := leeHasta(t, r, "SW1>"); strings.Contains(out, "MARCA-PW") {
		t.Fatalf("la contraseña apareció en la salida: %q", out)
	}
}

// El guard decide: una dirección no autorizada no se marca.
func TestTelnetSinPermisoDelGuard(t *testing.T) {
	ap := netip.MustParseAddrPort(simulator.StartTelnet(t, simulator.Config{Hostname: "SW1"}))
	_, err := OpenTelnet(context.Background(), NewGuard(nil, nil), "j", ap.Addr().String(), ap.Port(), TelnetOptions{})
	if !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("err = %v", err)
	}
}

// Ctx ya cancelado: ni se marca.
func TestTelnetCtxCancelado(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := OpenTelnet(ctx, NewGuard(nil, nil), "j", "192.0.2.1", 23, TelnetOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// Bytes sueltos: una IAC partida entre lecturas, IAC IAC en datos, un SB sin cerrar y el cierre del equipo.
func TestTelnetDecodificaBytesPartidos(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	s := newTelnetSession(b)
	defer s.Close()
	r, w, err := s.ShellSize("vt100", 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	var sent bytes.Buffer
	go io.Copy(&sent, a) // lo que el cliente contesta (negociación) y teclea
	go func() {
		for _, p := range [][]byte{{'h', 0xff}, {0xff, 'i', 0xff}, {0xfb}, {1, '\r'}, {0, 'x', 0xff, 0xfa, 31}, bytes.Repeat([]byte{'z'}, 100)} {
			a.Write(p)
		}
		a.Close()
	}()
	out, _ := io.ReadAll(r)
	if !bytes.HasPrefix(out, []byte("h\xffi\rx")) || bytes.Contains(out, []byte("z")) { // un SB largo se descarta entero, no se muestra
		t.Fatalf("salida = %q", out)
	}
	if _, err := w.Write([]byte("\xff\r")); err == nil {
		t.Error("escribió después del cierre del equipo")
	}
}

// Lo tecleado sale con 0xFF duplicado y el Enter (CR solo) como CR NUL; CR LF queda igual.
func TestTelnetEscribeIACYCR(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	s := newTelnetSession(b)
	defer s.Close()
	_, w, err := s.ShellSize("vt100", 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	go w.Write([]byte("a\xffb\rc\r\n"))
	want := []byte("a\xff\xffb\r\x00c\r\n")
	got := make([]byte, len(want))
	if _, err := io.ReadFull(a, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("enviado = %q (%v), quería %q", got, err, want)
	}
}

// equipoFalso es el lado del equipo sobre net.Pipe: lo que el cliente manda se junta en got (lo lee una goroutine,
// el pipe no tiene búfer) y la salida del cliente se descarta.
type equipoFalso struct {
	a   net.Conn
	got chan byte
}

func nuevoEquipoFalso(t *testing.T) (*equipoFalso, *TelnetSession, io.Reader) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { a.Close() })
	s := newTelnetSession(b)
	t.Cleanup(func() { s.Close() })
	r, _, err := s.ShellSize("vt100", 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	e := &equipoFalso{a: a, got: make(chan byte, 1024)}
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := a.Read(buf)
			for _, c := range buf[:n] {
				e.got <- c
			}
			if err != nil {
				close(e.got)
				return
			}
		}
	}()
	return e, s, r
}

// espera exige que el cliente mande exactamente want como lo siguiente.
func (e *equipoFalso) espera(t *testing.T, want []byte) {
	t.Helper()
	for i, w := range want {
		select {
		case c := <-e.got:
			if c != w {
				t.Fatalf("byte %d = %d, quería %v", i, c, want)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no llegó %v (faltó desde el byte %d)", want, i)
		}
	}
}

// nada exige que el cliente no mande nada durante un rato.
func (e *equipoFalso) nada(t *testing.T) {
	t.Helper()
	select {
	case c := <-e.got:
		t.Fatalf("mandó %d sin que hiciera falta", c)
	case <-time.After(200 * time.Millisecond):
	}
}

// Revisión de 48-1: el estado de cada opción se sigue (RFC 854/1143). Un WONT/DONT sobre una opción activa se
// acusa, la opción se puede volver a pedir y un pedido que no cambia nada no se contesta (sin bucles).
func TestTelnetEstadoDeOpciones(t *testing.T) {
	e, s, r := nuevoEquipoFalso(t)
	go io.Copy(io.Discard, r)
	e.a.Write([]byte{255, 251, 1})
	e.espera(t, []byte{255, 253, 1}) // WILL ECHO → DO ECHO
	e.a.Write([]byte{255, 251, 1})
	e.nada(t) // ya activa: no se contesta
	e.a.Write([]byte{255, 252, 1})
	e.espera(t, []byte{255, 254, 1}) // WONT ECHO → DONT ECHO
	e.a.Write([]byte{255, 251, 1})
	e.espera(t, []byte{255, 253, 1}) // y se puede volver a activar
	e.a.Write([]byte{255, 253, 31})
	e.espera(t, []byte{255, 251, 31, 255, 250, 31, 0, 80, 0, 24, 255, 240}) // DO NAWS → WILL NAWS y el tamaño
	e.a.Write([]byte{255, 254, 31})
	e.espera(t, []byte{255, 252, 31}) // DONT NAWS → WONT NAWS
	if err := s.Resize(30, 100); err != nil {
		t.Fatal(err)
	}
	e.nada(t) // NAWS apagado: Resize no avisa
	e.a.Write([]byte{255, 253, 31})
	e.espera(t, []byte{255, 251, 31, 255, 250, 31, 0, 100, 0, 30, 255, 240})
}

// Lo ya leído no espera a una IAC que llega partida: «Password: » se entrega aunque la negociación siga a medias.
func TestTelnetNoRetieneDatosAntesDeUnaIAC(t *testing.T) {
	e, _, r := nuevoEquipoFalso(t)
	go e.a.Write([]byte("Password: \xff"))
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := r.Read(buf)
		got <- string(buf[:n])
	}()
	select {
	case s := <-got:
		if s != "Password: " {
			t.Fatalf("leyó %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("retuvo «Password: » esperando el resto de la IAC")
	}
}

// Revisión de 48-1: con el teclado trabado (el equipo no lee mientras devuelve un pegado grande), una negociación a
// media sesión no traba al lector: su respuesta se encola y la salida sigue llegando.
func TestTelnetNegociacionConTecladoTrabado(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	s := newTelnetSession(b)
	defer s.Close()
	r, w, err := s.ShellSize("vt100", 24, 80)
	if err != nil {
		t.Fatal(err)
	}
	go w.Write([]byte("pegado grande\r")) // nadie lo lee todavía: el escritor queda bloqueado en el pipe
	go a.Write([]byte{255, 251, 1, 'x'})  // WILL ECHO y un dato
	got := make(chan byte, 1)
	go func() {
		buf := make([]byte, 1)
		if _, err := r.Read(buf); err == nil {
			got <- buf[0]
		}
	}()
	select {
	case c := <-got:
		if c != 'x' {
			t.Fatalf("leyó %q", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("la negociación trabó al lector detrás del teclado")
	}
}
