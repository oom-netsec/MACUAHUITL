//go:build linux

package field

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/serialcon"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// consoleStream: el cliente de la consola en la prueba. Lo que se manda llega por in; lo que el núcleo envía, por out.
type consoleStream struct {
	v1.FieldService_ConsoleServer // solo se usan Context, Send y Recv
	ctx                           context.Context
	in                            chan *v1.ConsoleRequest
	out                           chan *v1.ConsoleResponse
}

func (c *consoleStream) Context() context.Context { return c.ctx }
func (c *consoleStream) Send(m *v1.ConsoleResponse) error {
	c.out <- m
	return nil
}
func (c *consoleStream) Recv() (*v1.ConsoleRequest, error) {
	m, ok := <-c.in
	if !ok {
		return nil, io.EOF
	}
	return m, nil
}

// consola: una sesión de consola contra una pty que hace de equipo.
type consola struct {
	t    *testing.T
	dev  *os.File
	st   *consoleStream
	d    *servicetest.Deps
	done chan error
	seen strings.Builder
}

func abrirConsola(t *testing.T) *consola {
	t.Helper()
	m, path, err := serialcon.Pty()
	if err != nil {
		t.Skip("sin pty:", err)
	}
	t.Cleanup(func() { m.Close() })
	d := servicetest.New(t)
	c := &consola{t: t, dev: m, d: d, done: make(chan error, 1),
		st: &consoleStream{ctx: context.Background(), in: make(chan *v1.ConsoleRequest, 8), out: make(chan *v1.ConsoleResponse, 1024)}}
	c.st.in <- &v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Open{Open: &v1.ConsoleOpen{Port: path}}}
	go func() { c.done <- (&fieldSvc{d: d}).Console(c.st) }()
	<-c.st.out // abierto
	return c
}

// equipo: lo que devuelve el equipo; espera a que el cliente lo reciba.
func (c *consola) equipo(s string) {
	c.t.Helper()
	io.WriteString(c.dev, s)
	deadline := time.After(10 * time.Second)
	for !strings.HasSuffix(c.seen.String(), s) {
		select {
		case r := <-c.st.out:
			c.seen.Write(r.GetData())
		case <-deadline:
			c.t.Fatalf("no llegó %q; visto: %q", s, c.seen.String())
		}
	}
}

// teclea: lo tecleado; espera a que el equipo lo reciba tal cual.
func (c *consola) teclea(s string) {
	c.t.Helper()
	c.st.in <- &v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Data{Data: []byte(s)}}
	got := make([]byte, 0, len(s))
	buf := make([]byte, 256)
	for len(got) < len(s) {
		n, err := c.dev.Read(buf)
		if err != nil {
			c.t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	if !strings.Contains(strings.ReplaceAll(string(got), "\n", "\r"), strings.TrimRight(s, "\r")) {
		c.t.Fatalf("al equipo no le llegó lo tecleado: %q", got)
	}
}

// cerrar cierra la sesión y devuelve la grabación.
func (c *consola) cerrar() string {
	c.t.Helper()
	close(c.st.in)
	select {
	case err := <-c.done:
		if err != nil {
			c.t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		c.t.Fatal("la consola no cerró")
	}
	logs, _ := filepath.Glob(filepath.Join(c.d.Outputs(), "console", "console_*.log"))
	if len(logs) != 1 {
		c.t.Fatalf("grabaciones: %v", logs)
	}
	b, err := os.ReadFile(logs[0])
	if err != nil {
		c.t.Fatal(err)
	}
	rec := string(b)
	if lines := strings.Split(strings.TrimSpace(rec), "\n"); !strings.Contains(lines[len(lines)-1], "### cerrado") {
		c.t.Errorf("la marca de cierre no es la última línea:\n%s", rec)
	}
	return rec
}

func sinSecretos(t *testing.T, rec string, secretos ...string) {
	t.Helper()
	for _, sec := range secretos {
		if strings.Contains(rec, sec) {
			t.Errorf("la grabación deja ver %q:\n%s", sec, rec)
		}
	}
}

// La grabación de la consola serie enmascara como la de la terminal: la configuración que devuelve el equipo y el
// eco de lo tecleado no dejan secretos en outputs/console.
func TestConsoleRecordingMasksSecrets(t *testing.T) {
	c := abrirConsola(t)
	c.equipo("Switch#show running-config\r\n" +
		"enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0\r\n" +
		"username admin privilege 15 password 7 0822455D0A16\r\n" +
		"snmp-server community S3cr3tRW RW\r\n" +
		"tacacs-server key 0 LlaveTacacs99\r\n" +
		"Switch(config)#")
	c.teclea("username ops secret 0 Tecl3adoSecreto\r")
	c.equipo("username ops secret 0 Tecl3adoSecreto\r\nSwitch(config)#")
	rec := c.cerrar()
	sinSecretos(t, rec, "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0", "0822455D0A16", "S3cr3tRW", "LlaveTacacs99", "Tecl3adoSecreto")
	if strings.Contains(rec, ">>>") {
		t.Errorf("la consola grabó lo tecleado:\n%s", rec)
	}
	for _, keep := range []string{"show running-config", "snmp-server community <MASKED:", "Switch(config)#username ops secret 0 <MASKED:", "### abierto"} {
		if !strings.Contains(rec, keep) {
			t.Errorf("la grabación no trae %q:\n%s", keep, rec)
		}
	}
}

// Login en la consola: el eco del Enter llega aparte y la contraseña empieza a teclearse antes de «Password:»; y el
// diálogo setup devuelve el secreto tecleado. Nada de eso queda en la grabación; el eco del usuario sí.
func TestConsoleRecordingPasswordPrompts(t *testing.T) {
	c := abrirConsola(t)
	c.equipo("\r\nUser Access Verification\r\n\r\nUsername: ")
	c.teclea("admin\r")
	c.equipo("admin")
	c.equipo("\r\n")
	c.teclea("C")
	c.equipo("Password: ")
	c.teclea("isco12345\r")
	c.equipo("\r\nSwitch>")
	c.teclea("enable\r")
	c.equipo("enable\r\n")
	c.teclea("E")
	c.equipo("Password: ")
	c.teclea("n4bleS3c\r")
	c.equipo("\r\nSwitch#")
	c.equipo("\r\n  Enter enable secret: ")
	for _, k := range "Setup5ecret" {
		c.teclea(string(k))
		c.equipo(string(k))
	}
	c.teclea("\r")
	c.equipo("\r\n  Next: ")
	rec := c.cerrar()
	sinSecretos(t, rec, "Cisco12345", "isco12345", "En4bleS3c", "n4bleS3c", "Setup5ecret", ">>>")
	if !strings.Contains(rec, "Username: admin") {
		t.Errorf("falta el eco del usuario:\n%s", rec)
	}
}

// Al reabrir la consola el equipo puede seguir en «Password:» sin mandar nada: lo tecleado a ciegas no se graba.
func TestConsoleRecordingBlindStart(t *testing.T) {
	c := abrirConsola(t)
	c.teclea("Blind0Pass\r")
	c.equipo("\r\nSwitch>")
	rec := c.cerrar()
	sinSecretos(t, rec, "Blind0Pass")
}
