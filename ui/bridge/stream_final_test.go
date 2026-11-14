package bridge

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// finalEvents manda un estado y se queda abierto hasta que el cliente cierra el stream.
type finalEvents struct {
	v1.UnimplementedEventServiceServer
	state string
	mu    sync.Mutex
	opens int
	done  chan struct{}
}

func (f *finalEvents) Subscribe(r *v1.SubscribeRequest, st v1.EventService_SubscribeServer) error {
	f.mu.Lock()
	f.opens++
	f.mu.Unlock()
	st.Send(&v1.SubscribeResponse{JobId: r.JobIds[0], Event: &v1.SubscribeResponse_JobStateChanged{JobStateChanged: &v1.JobStateChanged{State: f.state}}})
	<-st.Context().Done()
	f.done <- struct{}{}
	return nil
}

// Un jobStateChanged final cierra el stream del trabajo y lo borra del mapa; resubscribe no lo reabre.
func TestStreamSeCierraAlEstadoFinal(t *testing.T) {
	for _, state := range []string{"completed", "cancelled", "failed", "round.end"} {
		d, _ := os.MkdirTemp("", "brg")
		defer os.RemoveAll(d)
		sock := filepath.Join(d, "core.sock")
		l, err := ipc.Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		fe := &finalEvents{state: state, done: make(chan struct{}, 4)}
		sctx, stop := context.WithCancel(context.Background())
		defer stop()
		go ipc.Serve(sctx, l, func(r ipc.Registrar) { v1.RegisterEventServiceServer(r, fe) })
		b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
		b.ctx = sctx
		if err := b.Subscribe(sctx, []string{"j1"}); err != nil {
			t.Fatal(err)
		}
		final := state != "round.end"
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
