package bridge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

type fakeTerminal struct {
	v1.UnimplementedTerminalServiceServer
	got chan string
}

// OpenTerminal hace eco: lo recibido vuelve como salida del equipo.
func (f fakeTerminal) OpenTerminal(st v1.TerminalService_OpenTerminalServer) error {
	m, _ := st.Recv()
	o := m.GetOpen()
	f.got <- "open " + o.Address + " " + o.CredentialId + " " + o.AcceptedHostKeyFingerprints[0]
	st.Send(&v1.OpenTerminalResponse{Opened: "admin@" + o.Address, Recording: "/o/t.log"})
	for {
		m, err := st.Recv()
		if err == io.EOF {
			f.got <- "closed"
			return nil
		}
		if err != nil {
			return err
		}
		if sz := m.GetResize(); sz != nil {
			f.got <- "resize"
			continue
		}
		st.Send(&v1.OpenTerminalResponse{Data: m.GetData()})
	}
}

func TestTerminalBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := ipctest.Addr(d)
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ft := fakeTerminal{got: make(chan string, 4)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterTerminalServiceServer(r, ft) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	id, err := b.TerminalOpen(TerminalDTO{Address: "192.0.2.1", CredentialID: "c1", Accept: []string{"SHA256:x"}})
	if err != nil {
		t.Fatal(err)
	}
	if g := <-ft.got; g != "open 192.0.2.1 c1 SHA256:x" {
		t.Fatalf("open = %q", g)
	}
	rec.waitFor(t, `terminal:opened {"opened":"admin@192.0.2.1","recording":"/o/t.log","runId":"`+id+`"}`)
	if err := b.TerminalSend(id, "show ver\r"); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `terminal:data {"data":"show ver\r","runId":"`+id+`"}`)
	if err := b.TerminalResize(id, 40, 120); err != nil || <-ft.got != "resize" {
		t.Fatal(err)
	}
	if err := b.TerminalClose(id); err != nil || <-ft.got != "closed" {
		t.Fatal(err)
	}
	rec.waitFor(t, `terminal:done {"runId":"`+id+`"}`)
	if err := b.TerminalSend(id, "x"); err == nil {
		t.Fatal("envío a una terminal cerrada")
	}
}

// authTerminal es un núcleo falso en modo tecleado: lee el open, pregunta (usuario + contraseña sin eco) y reporta lo que llega.
type authTerminal struct {
	v1.UnimplementedTerminalServiceServer
	got chan string
}

func (f authTerminal) OpenTerminal(st v1.TerminalService_OpenTerminalServer) error {
	m, _ := st.Recv()
	o := m.GetOpen()
	f.got <- "open " + o.Address + " cred=" + o.CredentialId + " user=" + o.Username
	st.Send(&v1.OpenTerminalResponse{AuthPrompt: &v1.AuthPrompt{Seq: 1, Name: "MFA", Instruction: "<b>x</b>", Prompts: []*v1.AuthQuestion{{Text: "login as: ", Echo: true}, {Text: "Password: ", Echo: false}}}})
	m, err := st.Recv()
	if err != nil {
		f.got <- "abort-before-answer"
		return nil
	}
	if a := m.GetAuthAnswer(); a != nil {
		f.got <- fmt.Sprintf("answer %d %q %q", a.Seq, a.Answers[0], a.Answers[1])
	}
	for {
		if _, err := st.Recv(); err != nil {
			f.got <- "closed"
			return nil
		}
	}
}

func TestTerminalAuthBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := ipctest.Addr(d)
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ft := authTerminal{got: make(chan string, 4)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterTerminalServiceServer(r, ft) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	id, err := b.TerminalOpen(TerminalDTO{Address: "192.0.2.1", Username: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if g := <-ft.got; g != "open 192.0.2.1 cred= user=admin" {
		t.Fatalf("open = %q", g)
	}
	rec.waitFor(t, `terminal:auth {"instruction":"`+"\\u003cb\\u003ex\\u003c/b\\u003e"+`","name":"MFA","prompts":[{"echo":true,"text":"login as: "},{"echo":false,"text":"Password: "}],"runId":"`+id+`","seq":1}`)
	if err := b.TerminalAnswer(id, 1, []string{"u", "s3cr3t"}); err != nil {
		t.Fatal(err)
	}
	if g := <-ft.got; g != `answer 1 "u" "s3cr3t"` {
		t.Fatalf("answer = %q", g)
	}
	// Cerrar la pestaña con la sesión viva (o con una pregunta abierta) cierra el envío: el núcleo aborta.
	if err := b.TerminalClose(id); err != nil || <-ft.got != "closed" {
		t.Fatal(err)
	}
}

// El usuario viaja en modo tecleado (con dirección o con host guardado); con credencial explícita no. Con hostId decide el núcleo.
func TestTerminalUsernameSoloTecleado(t *testing.T) {
	if u := (TerminalDTO{Address: "a", CredentialID: "c", Username: "x"}).open().Username; u != "" {
		t.Fatalf("con credencial: %q", u)
	}
	if u := (TerminalDTO{HostID: "h", Username: "x"}).open().Username; u != "x" {
		t.Fatalf("con host guardado debe viajar: %q", u)
	}
	if u := (TerminalDTO{Address: "a", Username: "x"}).open().Username; u != "x" {
		t.Fatalf("tecleado: %q", u)
	}
}

// Cerrar la pestaña con la pregunta sin contestar llega al núcleo como fin del envío.
func TestTerminalCerrarEnPregunta(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := ipctest.Addr(d)
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ft := authTerminal{got: make(chan string, 4)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterTerminalServiceServer(r, ft) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	id, err := b.TerminalOpen(TerminalDTO{Address: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	<-ft.got
	if err := b.TerminalClose(id); err != nil {
		t.Fatal(err)
	}
	if g := <-ft.got; g != "abort-before-answer" {
		t.Fatalf("got %q", g)
	}
}

// rondasTerminal pregunta dos veces (seq 1 y 2) y reporta lo recibido; nunca repite los secretos.
type rondasTerminal struct {
	v1.UnimplementedTerminalServiceServer
	got chan string
}

func (f rondasTerminal) OpenTerminal(st v1.TerminalService_OpenTerminalServer) error {
	if _, err := st.Recv(); err != nil {
		return err
	}
	for seq := uint32(1); seq <= 2; seq++ {
		st.Send(&v1.OpenTerminalResponse{AuthPrompt: &v1.AuthPrompt{Seq: seq, Prompts: []*v1.AuthQuestion{{Text: "Password: "}}}})
		m, err := st.Recv()
		if err != nil {
			return nil
		}
		a := m.GetAuthAnswer()
		f.got <- fmt.Sprintf("answer %d %q", a.Seq, a.Answers[0])
	}
	st.Send(&v1.OpenTerminalResponse{Opened: "ok"})
	for {
		if _, err := st.Recv(); err != nil {
			return nil
		}
	}
}

func rondasSetup(t *testing.T) (*Bridge, *recorder, rondasTerminal) {
	d, _ := os.MkdirTemp("", "brg")
	t.Cleanup(func() { os.RemoveAll(d) })
	sock := ipctest.Addr(d)
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ft := rondasTerminal{got: make(chan string, 4)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterTerminalServiceServer(r, ft) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	return b, rec, ft
}

// Varias rondas: cada pregunta (seq 1 y 2) se emite y se contesta con su seq; los eventos emitidos no llevan el secreto.
func TestTerminalVariasRondasSinSecretoEnEventos(t *testing.T) {
	const secreto = "S3cr3to-marcador"
	b, rec, ft := rondasSetup(t)
	id, err := b.TerminalOpen(TerminalDTO{Address: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `terminal:auth {"instruction":"","name":"","prompts":[{"echo":false,"text":"Password: "}],"runId":"`+id+`","seq":1}`)
	if err := b.TerminalAnswer(id, 1, []string{secreto}); err != nil {
		t.Fatal(err)
	}
	if g := <-ft.got; g != `answer 1 "`+secreto+`"` {
		t.Fatalf("ronda 1: %q", g)
	}
	rec.waitFor(t, `terminal:auth {"instruction":"","name":"","prompts":[{"echo":false,"text":"Password: "}],"runId":"`+id+`","seq":2}`)
	if err := b.TerminalAnswer(id, 2, []string{secreto + "2"}); err != nil {
		t.Fatal(err)
	}
	if g := <-ft.got; g != `answer 2 "`+secreto+`2"` {
		t.Fatalf("ronda 2: %q", g)
	}
	rec.waitFor(t, `terminal:opened {"opened":"ok","recording":"","runId":"`+id+`"}`)
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, e := range rec.evs {
		if strings.Contains(e, secreto) {
			t.Fatalf("el evento lleva el secreto: %s", e)
		}
	}
}

// Los bytes de las respuestas se ponen en ceros al volver (si se quita el clear, esta prueba falla).
func TestTerminalAnswerPoneEnCerosLosBytes(t *testing.T) {
	b, rec, _ := rondasSetup(t)
	id, err := b.TerminalOpen(TerminalDTO{Address: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `terminal:auth {"instruction":"","name":"","prompts":[{"echo":false,"text":"Password: "}],"runId":"`+id+`","seq":1}`)
	called := false
	err = b.terminalAnswer(id, 1, []string{"secreto"}, func(bs [][]byte) {
		called = true
		for _, x := range bs {
			if !bytes.Equal(x, make([]byte, len(x))) {
				t.Errorf("quedó sin borrar: %q", x)
			}
		}
	})
	if err != nil || !called {
		t.Fatal(err, called)
	}
}
