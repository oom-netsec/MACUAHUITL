package bridge

import (
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// fakeResolved: el primer evento de Run trae run_id y resolved, sin línea.
type fakeResolved struct {
	v1.UnimplementedDiagServiceServer
}

func (fakeResolved) Run(_ *v1.RunRequest, st v1.DiagService_RunServer) error {
	st.Send(&v1.RunResponse{RunId: "core-1", Resolved: &v1.ResolvedTarget{Name: "sw1.lab", Ip: "fe80::1%eth0", Family: "ipv6"}})
	st.Send(&v1.RunResponse{OutputLine: "PING"})
	return st.Send(&v1.RunResponse{Done: true})
}

func TestDiagRunReenviaResolved(t *testing.T) {
	b, rec := startServices(t, func(r ipc.Registrar) { v1.RegisterDiagServiceServer(r, fakeResolved{}) })
	if _, err := b.DiagRun("ping", []string{"sw1.lab"}, nil); err != nil {
		t.Fatal(err)
	}
	waitCount(rec, "diag:done", 1)
	rec.mu.Lock()
	evs := strings.Join(rec.evs, "\n")
	rec.mu.Unlock()
	if !strings.Contains(evs, `diag:line {"resolved":{"family":"ipv6","ip":"fe80::1%eth0","name":"sw1.lab"},"runId":"run-1"}`) {
		t.Fatalf("diag:line sin resolved: %s", evs)
	}
	if strings.Count(evs, `"resolved"`) != 1 || strings.Contains(evs, "core-1") {
		t.Fatalf("resolved debe salir una vez y sin el id del núcleo: %s", evs)
	}
}
