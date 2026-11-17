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
