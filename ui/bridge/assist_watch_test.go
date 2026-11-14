package bridge

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// vivoAssist repite el historial desde el evento 0 y deja el stream abierto hasta que se cancela.
type vivoAssist struct {
	v1.UnimplementedAssistServiceServer
	opens atomic.Int32
	live  atomic.Int32
}

func (f *vivoAssist) WatchRun(_ *v1.WatchRunRequest, st v1.AssistService_WatchRunServer) error {
	f.opens.Add(1)
	f.live.Add(1)
	defer f.live.Add(-1)
	st.Send(&v1.WatchRunResponse{Event: &v1.AssistEvent{Kind: "state", State: "running"}})
	<-st.Context().Done()
	return nil
}

func TestAssistWatchUnoPorRunIdPorReemplazo(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	f := &vivoAssist{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterAssistServiceServer(r, f) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	bctx, bstop := context.WithCancel(ctx)
	b.ctx = bctx
	for i := 0; i < 2; i++ {
		if err := b.AssistWatch("r1"); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(500 * time.Millisecond)
	if n := f.live.Load(); n != 1 {
		t.Fatalf("streams vivos = %d; quería 1", n)
	}
	events, dones := 0, 0
	rec.mu.Lock()
	for _, e := range rec.evs {
		switch {
		case strings.HasPrefix(e, "assist:event"):
			events++
		case strings.HasPrefix(e, "assist:done"):
			dones++
		}
	}
	rec.mu.Unlock()
	if events < 1 || events > 2 || dones != 0 { // el segundo watch repite desde 0; el reemplazado no emite done
		t.Fatalf("eventos=%d done=%d", events, dones)
	}
	b.mu.Lock()
	n := len(b.assists)
	b.mu.Unlock()
	if n != 1 {
		t.Fatalf("registrados = %d", n)
	}
	bstop() // el cierre del puente lo cancela
	time.Sleep(300 * time.Millisecond)
	if n := f.live.Load(); n != 0 {
		t.Fatalf("quedaron %d vivos", n)
	}
}
