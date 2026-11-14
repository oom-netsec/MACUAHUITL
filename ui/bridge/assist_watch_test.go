package bridge

import (
	"context"
	"os"
	"path/filepath"
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
	// finish, si no es nil, hace que la ejecución termine (EOF) al cerrarse el canal.
	finish chan struct{}
}

func (f *vivoAssist) WatchRun(_ *v1.WatchRunRequest, st v1.AssistService_WatchRunServer) error {
	f.opens.Add(1)
	f.live.Add(1)
	defer f.live.Add(-1)
	st.Send(&v1.WatchRunResponse{Event: &v1.AssistEvent{Kind: "state", State: "running"}})
	if f.finish != nil {
		select {
		case <-f.finish:
		case <-st.Context().Done():
		}
		return nil
	}
	<-st.Context().Done()
	return nil
}

// espera sondea hasta que cond se cumpla (plazo generoso); falla si no.
func espera(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("no ocurrió: " + msg)
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
	espera(t, "un solo stream vivo con su evento", func() bool { return f.opens.Load() >= 1 && f.live.Load() == 1 && rec.count("assist:event") >= 1 })
	if ev := rec.count("assist:event"); ev > 2 || rec.count("assist:done") != 0 { // el segundo watch repite desde 0; el reemplazado no emite done
		t.Fatalf("eventos=%d done=%d", ev, rec.count("assist:done"))
	}
	b.mu.Lock()
	n := len(b.assists)
	b.mu.Unlock()
	if n != 1 {
		t.Fatalf("registrados = %d", n)
	}
	bstop() // el cierre del puente lo cancela
	espera(t, "0 vivos al cerrar el puente", func() bool { return f.live.Load() == 0 })
}

func puenteAssist(t *testing.T, f *vivoAssist) (*Bridge, *recorder) {
	t.Helper()
	d, _ := os.MkdirTemp("", "brg")
	t.Cleanup(func() { os.RemoveAll(d) })
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterAssistServiceServer(r, f) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	b.ctx = ctx
	return b, rec
}

// Dos watch del mismo run en paralelo: ninguno devuelve error aunque uno cancele al otro mientras abre.
func TestAssistWatchParaleloNoDevuelveError(t *testing.T) {
	b, _ := puenteAssist(t, &vivoAssist{})
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func() { errs <- b.AssistWatch("r1") }()
	}
	for i := 0; i < 8; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("AssistWatch devolvió %v", err)
		}
	}
}

// Si la ejecución termina cuando otro watch ya reemplazó al viejo, el viejo sale en silencio.
func TestAssistWatchReemplazadoNoEmiteDone(t *testing.T) {
	f := &vivoAssist{finish: make(chan struct{})}
	b, rec := puenteAssist(t, f)
	if err := b.AssistWatch("r1"); err != nil {
		t.Fatal(err)
	}
	espera(t, "evento del primero", func() bool { return rec.count("assist:event") == 1 })
	b.mu.Lock()
	b.assists["r1"] = &stream{cancel: func() {}} // otro watch lo reemplazó
	b.mu.Unlock()
	close(f.finish)
	espera(t, "el viejo terminó", func() bool { return f.live.Load() == 0 })
	time.Sleep(100 * time.Millisecond) // margen para que un done indebido llegara
	if n := rec.count("assist:done"); n != 0 {
		t.Fatalf("assist:done = %d; el reemplazado debía salir en silencio", n)
	}
}
