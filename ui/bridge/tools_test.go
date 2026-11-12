package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeTools struct {
	v1.UnimplementedToolsServiceServer
	got chan *v1.DnsRequest
}

func (f fakeTools) Dns(_ context.Context, r *v1.DnsRequest) (*v1.DnsResponse, error) {
	f.got <- r
	return &v1.DnsResponse{Report: &v1.ToolReport{Text: "dns ok"}}, nil
}

func (fakeTools) Syslog(r *v1.SyslogRequest, st v1.ToolsService_SyslogServer) error {
	st.Send(&v1.SyslogResponse{Listening: "127.0.0.1:5514"})
	st.Send(&v1.SyslogResponse{Json: `{"Raw":"<14>hola"}`})
	<-st.Context().Done()
	return nil
}

func TestToolsBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ft := fakeTools{got: make(chan *v1.DnsRequest, 1)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterToolsServiceServer(r, ft) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	txt, err := b.ToolsDns(DnsDTO{Mode: "trace", Name: "example.com", Deep: true, Servers: []string{"1.1.1.1"}})
	if err != nil || txt != "dns ok" {
		t.Fatalf("%q %v", txt, err)
	}
	if r := <-ft.got; r.Mode != v1.DnsMode_DNS_MODE_TRACE || !r.Deep || r.Name != "example.com" {
		t.Fatalf("request = %+v", r)
	}
	if _, err := b.ToolsDns(DnsDTO{Mode: "frob"}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	id, err := b.SyslogStart("127.0.0.1:5514", "udp", false, false, SyslogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for rec.count("syslog:msg") < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := b.DiagCancel(id); err != nil {
		t.Fatal(err)
	}
	for rec.count("syslog:done") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rec.count("syslog:msg") != 2 || rec.count("syslog:done") != 1 {
		t.Fatalf("events = %v", rec.evs)
	}
}

// fakeSyslogOpts guarda lo que pidió la interfaz y devuelve un archivo nuevo y descartes.
type fakeSyslogOpts struct {
	v1.UnimplementedToolsServiceServer
	got chan *v1.SyslogRequest
}

func (f fakeSyslogOpts) Syslog(r *v1.SyslogRequest, st v1.ToolsService_SyslogServer) error {
	f.got <- r
	st.Send(&v1.SyslogResponse{Listening: "127.0.0.1:5514", OutputPath: "/o/syslog"})
	st.Send(&v1.SyslogResponse{RotatedPath: "/o/syslog/a.jsonl"})
	st.Send(&v1.SyslogResponse{Drops: &v1.SyslogDrops{Total: 7, PorOrigen: 5, Global: 1, ColaLlena: 1, SinceMs: 1793959200000, Top: []*v1.SyslogSourceDrops{{Source: "10.0.0.9", Count: 6}}}})
	<-st.Context().Done()
	return nil
}

func TestSyslogBridgeOptionsAndEvents(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := fakeSyslogOpts{got: make(chan *v1.SyslogRequest, 1)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterToolsServiceServer(r, f) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	if _, err := b.SyslogStart("127.0.0.1:5514", "udp", false, false, SyslogOptions{RatePerSource: 4294967396}); err == nil {
		t.Fatal("un valor fuera de int32 se truncó en silencio")
	}
	id, err := b.SyslogStart("127.0.0.1:5514", "tcp", false, true, SyslogOptions{
		RatePerSource: 50, BurstPerSource: 60, RateGlobal: 500, BurstGlobal: 600, QueueSize: 128,
		RotateMB: 5, RotateMinutes: 10, NameTemplate: "x_{fecha}", MaxFiles: 3, Format: "jsonl"})
	if err != nil {
		t.Fatal(err)
	}
	r := <-f.got
	if r.RatePerSource != 50 || r.BurstPerSource != 60 || r.RateGlobal != 500 || r.BurstGlobal != 600 || r.QueueSize != 128 ||
		r.RotateMb != 5 || r.RotateMinutes != 10 || r.NameTemplate != "x_{fecha}" || r.MaxFiles != 3 || r.Format != "jsonl" || !r.Save || r.Protocol != "tcp" {
		t.Fatalf("request = %+v", r)
	}
	rec.waitFor(t, `syslog:msg {"json":"","listening":"","outputPath":"","rotatedPath":"/o/syslog/a.jsonl","runId":"`+id+`"}`)
	rec.waitFor(t, `syslog:msg {"drops":{"total":7,"porOrigen":5,"global":1,"colaLlena":1,"sinceMs":1793959200000,"top":[{"source":"10.0.0.9","count":6}]},"json":"","listening":"","outputPath":"","rotatedPath":"","runId":"`+id+`"}`)
	b.DiagCancel(id)
}
