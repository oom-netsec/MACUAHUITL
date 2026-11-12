package bridge

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
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
	sock := filepath.Join(d, "core.sock")
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
