package bridge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// finalEvents manda un estado y se queda abierto hasta que el cliente cierra el stream.
type finalEvents struct {
	v1.UnimplementedEventServiceServer
	states []string
	mu     sync.Mutex
	opens  int
	done   chan struct{}
}

func (f *finalEvents) Subscribe(r *v1.SubscribeRequest, st v1.EventService_SubscribeServer) error {
	f.mu.Lock()
	f.opens++
	f.mu.Unlock()
	for _, state := range f.states {
		st.Send(&v1.SubscribeResponse{JobId: r.JobIds[0], Event: &v1.SubscribeResponse_JobStateChanged{JobStateChanged: &v1.JobStateChanged{State: state}}})
		if state == "completed" { // tras el final real vienen las fases de empaquetado
			st.Send(&v1.SubscribeResponse{JobId: r.JobIds[0], Event: &v1.SubscribeResponse_PhaseAdded{PhaseAdded: &v1.JobPhase{Kind: v1.JobPhaseKind_JOB_PHASE_KIND_PACKAGED}}})
		}
	}
	<-st.Context().Done()
	f.done <- struct{}{}
	return nil
}

// Solo el closed (tras el estado final y el empaquetado) cierra el stream del trabajo y lo borra del mapa; resubscribe no lo reabre.
func TestStreamSeCierraAlEstadoFinal(t *testing.T) {
	for _, states := range [][]string{{"completed", "closed"}, {"cancelled", "closed"}, {"failed", "closed"}, {"completed"}, {"cancelled"}, {"failed"}, {"round.end"}} {
		state := strings.Join(states, "+")
		d, _ := os.MkdirTemp("", "brg")
		defer os.RemoveAll(d)
		sock := filepath.Join(d, "core.sock")
		l, err := ipc.Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		fe := &finalEvents{states: states, done: make(chan struct{}, 4)}
		sctx, stop := context.WithCancel(context.Background())
		defer stop()
		go ipc.Serve(sctx, l, func(r ipc.Registrar) { v1.RegisterEventServiceServer(r, fe) })
		rec := &recorder{}
		b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
		b.ctx = sctx
		if err := b.Subscribe(sctx, []string{"j1"}); err != nil {
			t.Fatal(err)
		}
		final := states[len(states)-1] == "closed" // solo el closed cierra: completed/cancelled/failed van seguidos de empaquetado
		select {
		case <-fe.done:
			if !final {
				t.Fatalf("%s: cerró un stream que sigue vivo", state)
			}
		case <-time.After(500 * time.Millisecond):
			if final {
				t.Fatalf("%s: el stream sigue abierto", state)
			}
		}
		want := len(states)
		if states[0] == "completed" {
			want++ // la fase de empaquetado también se reenvía
		}
		if got := rec.count("core:event"); got != want {
			t.Fatalf("%s: %d eventos reenviados, quería %d: %v", state, got, want, rec.evs)
		}
		b.mu.Lock()
		n := len(b.streams)
		b.mu.Unlock()
		if want := map[bool]int{true: 0, false: 1}[final]; n != want {
			t.Fatalf("%s: %d streams, quería %d", state, n, want)
		}
		if final {
			b.resubscribe()
			time.Sleep(100 * time.Millisecond)
			fe.mu.Lock()
			opens := fe.opens
			fe.mu.Unlock()
			if opens != 1 {
				t.Fatalf("%s: resubscribe reabrió un trabajo terminado (%d aperturas)", state, opens)
			}
		}
		stop()
	}
}

// Subscribe lee st.dead con el candado mientras markDead lo escribe: sin carrera (go test -race).
func TestSubscribeNoCorreConMarkDead(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	sctx, stop := context.WithCancel(context.Background())
	defer stop()
	fe := &finalEvents{states: []string{"round.end"}, done: make(chan struct{}, 1000)}
	go ipc.Serve(sctx, l, func(r ipc.Registrar) { v1.RegisterEventServiceServer(r, fe) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	b.ctx = sctx
	if err := b.Subscribe(sctx, []string{"j1"}); err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	st := b.streams["j1"]
	b.mu.Unlock()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			b.Subscribe(sctx, []string{"j1"})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			b.mu.Lock()
			st.dead = i%2 == 0 // lo que hace markDead, con el candado
			b.mu.Unlock()
		}
	}()
	wg.Wait()
}
