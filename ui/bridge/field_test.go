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

type fakeField struct {
	v1.UnimplementedFieldServiceServer
	got chan string
}

func (fakeField) ListSerialPorts(context.Context, *v1.ListSerialPortsRequest) (*v1.ListSerialPortsResponse, error) {
	return &v1.ListSerialPortsResponse{Ports: []string{"/dev/ttyUSB0"}}, nil
}

// Console hace eco: lo recibido vuelve como salida del equipo.
func (f fakeField) Console(st v1.FieldService_ConsoleServer) error {
	m, _ := st.Recv()
	st.Send(&v1.ConsoleResponse{Opened: m.GetOpen().Port + " 9600 8N1", OutputPath: "/o/c.log"})
	for {
		m, err := st.Recv()
		if err == io.EOF {
			f.got <- "closed"
			return nil
		}
		if err != nil {
			return err
		}
		if m.GetSendBreak() {
			f.got <- "break"
			continue
		}
		st.Send(&v1.ConsoleResponse{Data: m.GetData()})
	}
}

func (fakeField) ServeFiles(r *v1.ServeFilesRequest, st v1.FieldService_ServeFilesServer) error {
	st.Send(&v1.ServeFilesResponse{Listening: r.Addr, Hint: "copy"})
	st.Send(&v1.ServeFilesResponse{TransferJson: `{"File":"a.bin"}`})
	<-st.Context().Done()
	return nil
}

func (fakeField) HashFile(_ context.Context, r *v1.HashFileRequest) (*v1.HashFileResponse, error) {
	return &v1.HashFileResponse{Report: &v1.ToolReport{Text: "MD5 x"}, Ok: r.Md5 == ""}, nil
}

func TestFieldBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ff := fakeField{got: make(chan string, 4)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterFieldServiceServer(r, ff) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	if p, err := b.FieldPorts(); err != nil || len(p) != 1 {
		t.Fatalf("%v %v", p, err)
	}
	id, err := b.ConsoleOpen(ConsoleDTO{Port: "/dev/ttyUSB0"})
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `console:opened {"opened":"/dev/ttyUSB0 9600 8N1","outputPath":"/o/c.log","runId":"`+id+`"}`)
	if err := b.ConsoleSend(id, "show ver\r"); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `console:data {"data":"show ver\r","runId":"`+id+`"}`)
	if err := b.ConsoleBreak(id); err != nil || <-ff.got != "break" {
		t.Fatal(err)
	}
	if err := b.ConsoleClose(id); err != nil || <-ff.got != "closed" {
		t.Fatal(err)
	}
	rec.waitFor(t, `console:done {"runId":"`+id+`"}`)
	if err := b.ConsoleSend(id, "x"); err == nil {
		t.Fatal("envío a una consola cerrada")
	}

	sid, err := b.ServeStart(ServeDTO{Protocol: "http", Addr: "127.0.0.1:8080", Files: []string{"/x/a.bin"}})
	if err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `serve:msg {"hint":"","listening":"","runId":"`+sid+`","transfer":"{\"File\":\"a.bin\"}"}`)
	b.DiagCancel(sid)
	rec.waitFor(t, `serve:done {"runId":"`+sid+`"}`)

	h, err := b.FieldHash("/x/a.bin", "", "")
	if err != nil || !h.Ok || h.Text != "MD5 x" {
		t.Fatalf("%+v %v", h, err)
	}
}
