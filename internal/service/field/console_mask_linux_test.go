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

// La grabación de la consola serie enmascara como la de la terminal: la configuración que devuelve el equipo y el
// eco de lo tecleado no dejan secretos en outputs/console.
func TestConsoleRecordingMasksSecrets(t *testing.T) {
	m, path, err := serialcon.Pty()
	if err != nil {
		t.Skip("sin pty:", err)
	}
	defer m.Close()
	d := servicetest.New(t)
	s := &fieldSvc{d: d}
	st := &consoleStream{ctx: context.Background(), in: make(chan *v1.ConsoleRequest, 8), out: make(chan *v1.ConsoleResponse, 1024)}
	st.in <- &v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Open{Open: &v1.ConsoleOpen{Port: path}}}
	done := make(chan error, 1)
	go func() { done <- s.Console(st) }()

	// waitFor: espera a que el cliente reciba text.
	var seen strings.Builder
	waitFor := func(text string) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for !strings.Contains(seen.String(), text) {
			select {
			case r := <-st.out:
				seen.Write(r.GetData())
			case <-deadline:
				t.Fatalf("no llegó %q; visto: %q", text, seen.String())
			}
		}
	}
	<-st.out // abierto
	io.WriteString(m, "Switch#show running-config\r\n"+
		"enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0\r\n"+
		"username admin privilege 15 password 7 0822455D0A16\r\n"+
		"snmp-server community S3cr3tRW RW\r\n"+
		"tacacs-server key 0 LlaveTacacs99\r\n"+
		"Switch(config)#")
	waitFor("Switch(config)#")

	// Lo tecleado: el equipo lo recibe tal cual y devuelve el eco, que se graba tapado.
	typed := "username ops secret 0 Tecl3adoSecreto\r"
	st.in <- &v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Data{Data: []byte(typed)}}
	got := make([]byte, 0, 64)
	buf := make([]byte, 64)
	for !strings.Contains(string(got), "\r") {
		n, err := m.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, buf[:n]...)
	}
	if !strings.Contains(string(got), "Tecl3adoSecreto") {
		t.Fatalf("al equipo no le llegó lo tecleado: %q", got)
	}
	io.WriteString(m, "username ops secret 0 Tecl3adoSecreto\r\nSwitch(config)#")
	waitFor("Tecl3adoSecreto\r\nSwitch(config)#")
	close(st.in)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("la consola no cerró")
	}

	logs, _ := filepath.Glob(filepath.Join(d.Outputs(), "console", "console_*.log"))
	if len(logs) != 1 {
		t.Fatalf("grabaciones: %v", logs)
	}
	b, err := os.ReadFile(logs[0])
	if err != nil {
		t.Fatal(err)
	}
	rec := string(b)
	for _, sec := range []string{"$1$mERr$hx5rVt7rPNoS4wqbXKX7m0", "0822455D0A16", "S3cr3tRW", "LlaveTacacs99", "Tecl3adoSecreto"} {
		if strings.Contains(rec, sec) {
			t.Errorf("la grabación deja ver %q", sec)
		}
	}
	if lines := strings.Split(strings.TrimSpace(rec), "\n"); !strings.Contains(lines[len(lines)-1], "### cerrado") {
		t.Errorf("la marca de cierre no es la última línea:\n%s", rec)
	}
	for _, keep := range []string{"show running-config", "snmp-server community <MASKED:", "username ops secret", "### abierto", "### cerrado"} {
		if !strings.Contains(rec, keep) {
			t.Errorf("la grabación no trae %q:\n%s", keep, rec)
		}
	}
}
