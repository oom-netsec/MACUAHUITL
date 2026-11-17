package bridge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakePing200 imita el ping extendido (#200): primer evento con run_id del núcleo, un punto de barrido, y al StopRun el resumen.
type fakePing200 struct {
	v1.UnimplementedDiagServiceServer
	stop chan struct{}
}

func (f fakePing200) Run(_ *v1.RunRequest, st v1.DiagService_RunServer) error {
	st.Send(&v1.RunResponse{RunId: "core-1", OutputLine: "PING 192.0.2.1"})
	st.Send(&v1.RunResponse{SweepPoint: &v1.SweepPoint{Size: 1472, Sent: 1, Received: 0, Result: "frag"}})
	select {
	case <-f.stop:
	case <-st.Context().Done():
		return nil
	}
	return st.Send(&v1.RunResponse{Done: true, PingSummary: &v1.PingSummary{Sent: 5, Received: 4, LossPct: 20, MinMs: 1.5, AvgMs: 2, MaxMs: 3, MdevMs: 0.4}})
}

func (f fakePing200) StopRun(_ context.Context, r *v1.StopRunRequest) (*v1.StopRunResponse, error) {
	if r.RunId != "core-1" {
		return nil, status.Error(codes.NotFound, "no run")
	}
	close(f.stop)
	return &v1.StopRunResponse{}, nil
}

func waitCount(rec *recorder, name string, n int) {
	for deadline := time.Now().Add(3 * time.Second); rec.count(name) < n && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
	}
}

func TestDiagPingExtendido200(t *testing.T) {
	b, rec := startServices(t, func(r ipc.Registrar) { v1.RegisterDiagServiceServer(r, fakePing200{stop: make(chan struct{})}) })
	id, err := b.DiagRun("ping", []string{"192.0.2.1"}, map[string]string{"continuous": "true"})
	if err != nil {
		t.Fatal(err)
	}
	waitCount(rec, "diag:line", 2)
	rec.mu.Lock()
	evs := strings.Join(rec.evs, "\n")
	rec.mu.Unlock()
	if !strings.Contains(evs, `"sweepPoint":{"received":0,"result":"frag","sent":1,"size":1472}`) || strings.Contains(evs, "core-1") {
		t.Fatalf("diag:line sin sweepPoint o filtra el id del núcleo: %s", evs)
	}
	// DiagStop usa el runId del puente y llega al núcleo con el suyo; el cierre trae el resumen.
	if err := b.DiagStop(id); err != nil {
		t.Fatal(err)
	}
	waitCount(rec, "diag:done", 1)
	rec.mu.Lock()
	evs = strings.Join(rec.evs, "\n")
	rec.mu.Unlock()
	if !strings.Contains(evs, `"pingSummary":{"avgMs":2,"lossPct":20,"maxMs":3,"mdevMs":0.4,"minMs":1.5,"received":4,"sent":5}`) {
		t.Fatalf("diag:done sin pingSummary: %s", evs)
	}
	// Terminada: DiagStop responde NotFound (la UI lo ignora), tanto si el puente ya no la tiene como si el núcleo no la conoce.
	err = b.DiagStop(id)
	var be *Error
	if !errors.As(err, &be) || be.Code != "NotFound" {
		t.Fatalf("DiagStop tras terminar = %v", err)
	}
}

// fakePingSinStop: núcleo que no manda run_id (o no tiene StopRun): el ping corre hasta que se corte el stream.
type fakePingSinStop struct {
	v1.UnimplementedDiagServiceServer
	runID string
}

func (f fakePingSinStop) Run(_ *v1.RunRequest, st v1.DiagService_RunServer) error {
	st.Send(&v1.RunResponse{RunId: f.runID, OutputLine: "PING 192.0.2.1"})
	<-st.Context().Done()
	return nil
}

// fakePingNotFound: el núcleo ya no conoce la ejecución (terminó entre medio).
type fakePingNotFound struct{ fakePingSinStop }

func (fakePingNotFound) StopRun(context.Context, *v1.StopRunRequest) (*v1.StopRunResponse, error) {
	return nil, status.Error(codes.NotFound, "ya terminó")
}

func TestDiagStopSinIDONiStopRunCorta(t *testing.T) {
	// Sin run_id del núcleo (núcleo viejo o aún no llegó el primer evento) y con StopRun Unimplemented: Detener corta como Cancelar.
	for _, runID := range []string{"", "core-1"} {
		b, rec := startServices(t, func(r ipc.Registrar) { v1.RegisterDiagServiceServer(r, fakePingSinStop{runID: runID}) })
		id, _ := b.DiagRun("ping", []string{"192.0.2.1"}, map[string]string{"continuous": "true"})
		waitCount(rec, "diag:line", 1)
		if err := b.DiagStop(id); err != nil {
			t.Fatalf("run_id %q: %v", runID, err)
		}
		waitCount(rec, "diag:done", 1)
		rec.mu.Lock()
		evs := strings.Join(rec.evs, "\n")
		rec.mu.Unlock()
		if !strings.Contains(evs, `"canceled":true`) {
			t.Fatalf("run_id %q: no se cortó: %s", runID, evs)
		}
	}
}

func TestDiagStopNotFoundDelNucleo(t *testing.T) {
	b, rec := startServices(t, func(r ipc.Registrar) {
		v1.RegisterDiagServiceServer(r, fakePingNotFound{fakePingSinStop{runID: "core-9"}})
	})
	id, _ := b.DiagRun("ping", []string{"192.0.2.1"}, map[string]string{"continuous": "true"})
	waitCount(rec, "diag:line", 1)
	var be *Error
	if err := b.DiagStop(id); !errors.As(err, &be) || be.Code != "NotFound" {
		t.Fatalf("NotFound del núcleo = %v", err)
	}
	b.DiagCancel(id)
}

// fakePingRunIDSolo: como el núcleo de 200-3, el primer evento trae solo run_id (sin línea); luego salida y cierre.
type fakePingRunIDSolo struct{ v1.UnimplementedDiagServiceServer }

func (fakePingRunIDSolo) Run(_ *v1.RunRequest, st v1.DiagService_RunServer) error {
	st.Send(&v1.RunResponse{RunId: "core-7"})
	st.Send(&v1.RunResponse{OutputLine: "64 bytes from 192.0.2.1"})
	st.Send(&v1.RunResponse{OutputLine: ""}) // una línea vacía de la salida sí se emite
	return st.Send(&v1.RunResponse{Done: true})
}

func TestDiagPrimerEventoSoloRunIDNoEsLinea(t *testing.T) {
	b, rec := startServices(t, func(r ipc.Registrar) { v1.RegisterDiagServiceServer(r, fakePingRunIDSolo{}) })
	if _, err := b.DiagRun("ping", []string{"192.0.2.1"}, nil); err != nil {
		t.Fatal(err)
	}
	waitCount(rec, "diag:done", 1)
	rec.mu.Lock()
	evs := strings.Join(rec.evs, "\n")
	rec.mu.Unlock()
	if rec.count("diag:line") != 2 || strings.Contains(evs, "core-7") || !strings.Contains(evs, `"line":"64 bytes from 192.0.2.1"`) || !strings.Contains(evs, `"line":""`) {
		t.Fatalf("eventos: %s", evs)
	}
}
