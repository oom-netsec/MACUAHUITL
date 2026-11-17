package main

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

// fakeDiag es un núcleo de diag que sigue un guion: primero run_id, luego los eventos; si wait, espera StopRun.
type fakeDiag struct {
	v1.UnimplementedDiagServiceServer
	events  []*v1.RunResponse
	final   *v1.RunResponse
	wait    bool
	noID    bool // no manda el run_id
	stopped chan string
	stops   atomic.Int32
}

func (f *fakeDiag) Run(_ *v1.RunRequest, st v1.DiagService_RunServer) error {
	if !f.noID {
		st.Send(&v1.RunResponse{RunId: "run-1"})
	}
	st.Send(&v1.RunResponse{OutputLine: "tick"}) // llega después del run_id: la prueba espera esta línea en vez de dormir
	for _, e := range f.events {
		st.Send(e)
	}
	if f.wait {
		select {
		case <-f.stopped:
		case <-st.Context().Done():
			return nil
		}
	}
	return st.Send(f.final)
}

func (f *fakeDiag) StopRun(_ context.Context, r *v1.StopRunRequest) (*v1.StopRunResponse, error) {
	f.stops.Add(1)
	if r.RunId == "run-1" && f.stopped != nil {
		close(f.stopped)
	}
	return &v1.StopRunResponse{}, nil
}

func startFakeDiag(t *testing.T, f *fakeDiag) {
	t.Helper()
	rt, _ := os.MkdirTemp("", "mctl")
	t.Cleanup(func() { os.RemoveAll(rt) })
	t.Setenv("XDG_RUNTIME_DIR", rt)
	ipctest.Isolate(t)
	sock, _ := ipc.SocketPath()
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	s := ipc.NewServer()
	v1.RegisterDiagServiceServer(s, f)
	go s.Serve(l)
	t.Cleanup(s.Stop)
}

func summary() *v1.PingSummary {
	return &v1.PingSummary{Sent: 5, Received: 4, LossPct: 20, MinMs: 1.5, AvgMs: 2, MaxMs: 3, MdevMs: 0.4}
}

func TestDiagPingResumen(t *testing.T) {
	startFakeDiag(t, &fakeDiag{events: []*v1.RunResponse{{OutputLine: "64 bytes"}}, final: &v1.RunResponse{Done: true, OutputPath: "/x", PingSummary: summary()}})
	out := must(t, "", "diag", "ping", "192.0.2.1")
	if strings.HasPrefix(out, "\n") || !strings.Contains(out, "5 enviados, 4 recibidos, 20 % de pérdida; min/avg/max/mdev = 1.5/2/3/0.4 ms") {
		t.Fatalf("out = %q", out)
	}
	if out = mustRaw(t, "", "--lang", "en", "diag", "ping", "192.0.2.1"); !strings.Contains(out, "5 sent, 4 received, 20 % loss; min/avg/max/mdev = 1.5/2/3/0.4 ms") {
		t.Fatalf("en: %q", out)
	}
}

func TestDiagPingSinRespuestasNoTraeTiempos(t *testing.T) {
	startFakeDiag(t, &fakeDiag{final: &v1.RunResponse{Done: true, PingSummary: &v1.PingSummary{Sent: 3, LossPct: 100}}})
	out := must(t, "", "diag", "ping", "192.0.2.1")
	if !strings.Contains(out, "3 enviados, 0 recibidos, 100 % de pérdida\n") || strings.Contains(out, "mdev") {
		t.Fatalf("out = %q", out)
	}
}

func TestDiagPingCtrlCLlamaStopRun(t *testing.T) {
	f := &fakeDiag{wait: true, stopped: make(chan string), final: &v1.RunResponse{Done: true, OutputPath: "/x", PingSummary: summary()}}
	startFakeDiag(t, f)
	sigs := fakeInterrupt(t)
	out, done := mctlAsync(strings.NewReader(""), "diag", "ping", "192.0.2.1", "-o", "continuous=true")
	waitOut(t, out, "tick", 1)
	sigs <- os.Interrupt
	if err := waitErr(t, done); err != nil {
		t.Fatal(err)
	}
	if f.stops.Load() != 1 || !strings.Contains(out.String(), "5 enviados, 4 recibidos") {
		t.Fatalf("stops=%d out=%q", f.stops.Load(), out.String())
	}
}

func TestDiagPingSegundoCtrlCCorta(t *testing.T) {
	f := &fakeDiag{wait: true, final: &v1.RunResponse{Done: true}}
	startFakeDiag(t, f)
	sigs := fakeInterrupt(t)
	code := make(chan int, 2)
	old := cli.Exit
	cli.Exit = func(c int) { code <- c }
	t.Cleanup(func() { cli.Exit = old })
	out, done := mctlAsync(strings.NewReader(""), "diag", "ping", "192.0.2.1", "-o", "continuous=true")
	waitOut(t, out, "tick", 1)
	sigs <- os.Interrupt
	for end := time.Now().Add(5 * time.Second); f.stops.Load() == 0 && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
	}
	if f.stops.Load() != 1 || !strings.Contains(out.String(), "deteniendo el ping") {
		t.Fatalf("el primer Ctrl-C debe llamar a StopRun: stops=%d out=%q", f.stops.Load(), out.String())
	}
	sigs <- os.Interrupt
	if err := waitErr(t, done); err == nil {
		t.Fatal("el segundo Ctrl-C debe cortar con error")
	}
	if c := waitCode(t, code); c != 130 || !strings.Contains(out.String(), "Segundo Ctrl-C") || strings.Contains(out.String(), "rpc error") {
		t.Fatalf("exit=%d out=%q", c, out.String())
	}
}

// Ctrl-C antes de que llegue el run_id no hay a quién detener: sale igual, con el mensaje del catálogo.
func TestDiagPingCtrlCSinRunID(t *testing.T) {
	f := &fakeDiag{wait: true, final: &v1.RunResponse{Done: true}, noID: true}
	startFakeDiag(t, f)
	sigs := fakeInterrupt(t)
	code := make(chan int, 1)
	old := cli.Exit
	cli.Exit = func(c int) { code <- c }
	t.Cleanup(func() { cli.Exit = old })
	out, done := mctlAsync(strings.NewReader(""), "diag", "ping", "192.0.2.1")
	waitOut(t, out, "tick", 1)
	sigs <- os.Interrupt
	waitErr(t, done)
	if c := waitCode(t, code); c != 130 || f.stops.Load() != 0 {
		t.Fatalf("exit=%d stops=%d", c, f.stops.Load())
	}
}

func TestDiagPingResumenRedondeado(t *testing.T) {
	startFakeDiag(t, &fakeDiag{final: &v1.RunResponse{Done: true, PingSummary: &v1.PingSummary{Sent: 3, Received: 2, LossPct: 100.0 / 3, MinMs: 1.234, AvgMs: 2.005, MaxMs: 3, MdevMs: 0.4999}}})
	out := must(t, "", "diag", "ping", "192.0.2.1")
	if !strings.Contains(out, "33.33 %") || strings.Contains(out, "33.333") || !strings.Contains(out, "= 1.23/2.01/3/0.5 ms") {
		t.Fatalf("out = %q", out)
	}
}

func sp(size int32, sent, rec int64, res string) *v1.RunResponse {
	return &v1.RunResponse{SweepPoint: &v1.SweepPoint{Size: size, Sent: sent, Received: rec, Result: res}}
}

func TestDiagPingBarridoTablaYMTU(t *testing.T) {
	f := &fakeDiag{events: []*v1.RunResponse{sp(1000, 2, 2, "ok"), sp(1472, 2, 2, "ok"), sp(1500, 2, 0, "frag"), sp(1600, 2, 0, "loss")},
		final: &v1.RunResponse{Done: true, PingSummary: summary()}}
	startFakeDiag(t, f)
	out := must(t, "", "diag", "ping", "192.0.2.1", "-o", "sweep_start=1000")
	for _, w := range []string{"tamaño", "resultado", "1472", "fragmenta", "pérdida", "MTU estimado: 1500"} {
		if !strings.Contains(out, w) {
			t.Fatalf("falta %q en:\n%s", w, out)
		}
	}
	out = mustRaw(t, "", "--lang", "en", "diag", "ping", "2001:db8::1")
	if !strings.Contains(out, "estimated MTU: 1520") {
		t.Fatalf("v6:\n%s", out)
	}
	// Destino por nombre sin family: no se adivina la versión de IP.
	if out = must(t, "", "diag", "ping", "host.example"); !strings.Contains(out, "MTU sin estimar") || strings.Contains(out, "MTU estimado") {
		t.Fatalf("nombre:\n%s", out)
	}
	if out = must(t, "", "diag", "ping", "host.example", "-o", "family=6"); !strings.Contains(out, "MTU estimado: 1520") {
		t.Fatalf("nombre con family=6:\n%s", out)
	}
	f.events = []*v1.RunResponse{sp(1000, 2, 2, "ok"), sp(1472, 2, 2, "ok")}
	if out = must(t, "", "diag", "ping", "192.0.2.1"); strings.Contains(out, "MTU") {
		t.Fatalf("sin frag no hay MTU:\n%s", out)
	}
}

func waitCode(t *testing.T, ch <-chan int) int {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("mctl no llamó a Exit")
		return 0
	}
}
