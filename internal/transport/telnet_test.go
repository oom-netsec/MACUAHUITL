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
	if !bytes.HasPrefix(out, []byte("h\xffi\rx")) || !bytes.Contains(out, []byte("zzzz")) { // tras el tope del SB vuelven los datos
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
