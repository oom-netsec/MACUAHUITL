//go:build !windows

package diag

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// recStream guarda los eventos que manda Run.
type recStream struct {
	v1.DiagService_RunServer
	ctx    context.Context
	mu     sync.Mutex
	events []*v1.RunResponse
}

func (r *recStream) Context() context.Context { return r.ctx }
func (r *recStream) Send(m *v1.RunResponse) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, m)
	return nil
}
func (r *recStream) snapshot() []*v1.RunResponse {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*v1.RunResponse(nil), r.events...)
}

// fakePing imprime una respuesta de 2 ms cada 50 ms y, con SIGINT, el resumen de iputils y sale.
func fakePing(t *testing.T) func(string) (string, error) {
	p := filepath.Join(t.TempDir(), "ping")
	script := `#!/bin/sh
trap 'echo "--- fake ping statistics ---"; exit 0' INT
i=1
while :; do
  echo "64 bytes from 192.0.2.1: icmp_seq=$i ttl=64 time=2.00 ms"
  i=$((i+1))
  sleep 0.05
done
`
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return func(string) (string, error) { return p, nil }
}

func startRun(t *testing.T, s *diagSvc) (*recStream, chan error) {
	st := &recStream{ctx: context.Background()}
	done := make(chan error, 1)
	go func() {
		done <- s.Run(&v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "192.0.2.1"}}, Options: map[string]string{"count": "100"}}, st)
	}()
	return st, done
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("tiempo agotado")
}

func TestStopRunDetieneYMandaResumen(t *testing.T) {
	d := servicetest.New(t)
	d.Look = fakePing(t)
	s := &diagSvc{d: d}
	st, done := startRun(t, s)
	waitFor(t, func() bool { return len(st.snapshot()) >= 4 })
	first := st.snapshot()[0]
	if first.RunId == "" || first.OutputLine != "" || first.Done {
		t.Fatalf("el primer evento debe traer solo run_id: %+v", first)
	}
	if _, err := s.StopRun(context.Background(), &v1.StopRunRequest{RunId: first.RunId}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	ev := st.snapshot()
	last := ev[len(ev)-1]
	sum := last.PingSummary
	if last.ExitCode != 0 { // salida ordenada por SIGINT (el trap sale con 0), no el respaldo SIGTERM (143)
		t.Errorf("exit_code = %d", last.ExitCode)
	}
	if !last.Done || sum == nil || sum.Sent < 3 || sum.Received != sum.Sent || sum.LossPct != 0 || sum.MinMs != 2 || sum.AvgMs != 2 || sum.MaxMs != 2 || sum.MdevMs != 0 {
		t.Fatalf("evento final: %+v", last)
	}
	// El resumen coincide con las respuestas que el cliente vio.
	lines := 0
	for _, e := range ev {
		if strings.Contains(e.OutputLine, "bytes from") {
			lines++
		}
	}
	if int64(lines) != sum.Received {
		t.Errorf("líneas %d, resumen %+v", lines, sum)
	}
	// Ya terminó: NOT_FOUND, y el registro quedó vacío.
	_, err := s.StopRun(context.Background(), &v1.StopRunRequest{RunId: first.RunId})
	if status.Code(err) != codes.NotFound {
		t.Errorf("tras terminar: %v", err)
	}
	if n := s.liveRuns(); n != 0 {
		t.Errorf("registro: %d", n)
	}
	if !strings.Contains(d.AuditText(), `diag.stop`) || !strings.Contains(d.AuditText(), first.RunId) {
		t.Errorf("sin auditoría diag.stop: %s", d.AuditText())
	}
	// diag.run y diag.done llevan run=<id> para ligarlos con diag.stop.
	if n := strings.Count(d.AuditText(), "run="+first.RunId); n != 2 {
		t.Errorf("run=%s en %d entradas, quería 2: %s", first.RunId, n, d.AuditText())
	}
}

func TestStopRunDesconocido(t *testing.T) {
	s := &diagSvc{d: servicetest.New(t)}
	_, err := s.StopRun(context.Background(), &v1.StopRunRequest{RunId: "nope"})
	if status.Code(err) != codes.NotFound || !strings.Contains(status.Convert(err).Message(), "ejecución") {
		t.Errorf("%v", err)
	}
}

// Cancelar el stream también saca la ejecución del registro; varios StopRun a la vez no chocan (-race).
func TestStopRunConcurrenteYCancelacion(t *testing.T) {
	d := servicetest.New(t)
	d.Look = fakePing(t)
	s := &diagSvc{d: d}
	st, done := startRun(t, s)
	waitFor(t, func() bool { return len(st.snapshot()) >= 2 })
	id := st.snapshot()[0].RunId
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); s.StopRun(context.Background(), &v1.StopRunRequest{RunId: id}) }()
	}
	wg.Wait()
	<-done
	if n := s.liveRuns(); n != 0 {
		t.Errorf("registro: %d", n)
	}

	ctx, cancel := context.WithCancel(context.Background())
	st2 := &recStream{ctx: ctx}
	done2 := make(chan error, 1)
	go func() {
		done2 <- s.Run(&v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "192.0.2.1"}}}, st2)
	}()
	waitFor(t, func() bool { return len(st2.snapshot()) >= 2 })
	cancel()
	<-done2
	if n := s.liveRuns(); n != 0 {
		t.Errorf("registro tras cancelar: %d", n)
	}
}

// Barrido por el servicio: sweep_point ok, ok, frag y el resumen total en el evento final; auditoría con run=.
func TestRunBarrido(t *testing.T) {
	d := servicetest.New(t)
	p := filepath.Join(t.TempDir(), "ping")
	script := `#!/bin/sh
size=56
while [ $# -gt 0 ]; do [ "$1" = "-s" ] && size=$2; shift; done
if [ "$size" -ge 1000 ]; then
  echo "ping: local error: message too long, mtu=1500"
  echo "1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms"
  exit 1
fi
echo "$((size+8)) bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=2.00 ms"
echo "1 packets transmitted, 1 received, 0% packet loss, time 0ms"
`
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	d.Look = func(string) (string, error) { return p, nil }
	s := &diagSvc{d: d}
	st := &recStream{ctx: context.Background()}
	err := s.Run(&v1.RunRequest{Tool: v1.DiagTool_DIAG_TOOL_PING, Targets: []*v1.Target{{Address: "192.0.2.1"}},
		Options: map[string]string{"sweep_start": "0", "sweep_end": "1000", "sweep_step": "500", "df": "true"}}, st)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	ev := st.snapshot()
	for _, e := range ev {
		if sp := e.SweepPoint; sp != nil {
			got = append(got, fmt.Sprintf("%d/%d/%d/%s", sp.Size, sp.Sent, sp.Received, sp.Result))
		}
	}
	if want := "0/1/1/ok 500/1/1/ok 1000/1/0/frag"; strings.Join(got, " ") != want {
		t.Errorf("puntos %q, quería %q", got, want)
	}
	last := ev[len(ev)-1]
	if sum := last.PingSummary; !last.Done || sum == nil || sum.Sent != 3 || sum.Received != 2 || sum.AvgMs != 2 {
		t.Errorf("final %+v", last)
	}
	if n := strings.Count(d.AuditText(), "run="+ev[0].RunId); n != 2 {
		t.Errorf("run= en %d entradas: %s", n, d.AuditText())
	}
	if n := strings.Count(d.AuditText(), "sweep=0-1000/500"); n != 2 { // diag.run y diag.done
		t.Errorf("sweep= en %d entradas: %s", n, d.AuditText())
	}
}
