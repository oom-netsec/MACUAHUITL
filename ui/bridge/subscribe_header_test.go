package bridge

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// headerEvents imita al núcleo: valida, se suscribe al bus (lento) y solo entonces manda los encabezados.
type headerEvents struct {
	v1.UnimplementedEventServiceServer
	missing    bool
	silent     bool // nunca manda encabezados (un núcleo atorado)
	empty      bool // termina sin error ni encabezados
	opens      atomic.Int32
	subscribed atomic.Bool
}

func (f *headerEvents) Subscribe(r *v1.SubscribeRequest, st v1.EventService_SubscribeServer) error {
	f.opens.Add(1)
	if f.missing {
		return status.Error(codes.NotFound, "no existe el trabajo")
	}
	if f.empty {
		return nil
	}
	if f.silent {
		<-st.Context().Done()
		return nil
	}
	time.Sleep(200 * time.Millisecond) // bus.Subscribe
	f.subscribed.Store(true)
	st.SendHeader(nil)
	<-st.Context().Done()
	return nil
}

func headerBridge(t *testing.T, f *headerEvents) *Bridge {
	t.Helper()
	d, _ := os.MkdirTemp("", "brg")
	t.Cleanup(func() { os.RemoveAll(d) })
	sock := filepath.Join(d, "core.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	sctx, stop := context.WithCancel(context.Background())
	t.Cleanup(stop)
	go ipc.Serve(sctx, l, func(r ipc.Registrar) { v1.RegisterEventServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	b.ctx = sctx
	return b
}

// El NotFound de un trabajo inexistente sale en el primer Recv, no al crear el stream: Subscribe lo devuelve.
func TestSubscribeDevuelveElNotFoundDelNucleo(t *testing.T) {
	b := headerBridge(t, &headerEvents{missing: true})
	err := b.Subscribe(b.ctx, []string{"nope"})
	var be *Error
	if !errors.As(err, &be) || be.Code != codes.NotFound.String() {
		t.Fatalf("err = %v; quería el NotFound del núcleo", err)
	}
}

// Subscribe vuelve cuando el núcleo ya está suscrito al bus: un evento publicado justo después (armed, la ronda 1)
// no se pierde.
func TestSubscribeVuelveConElNucleoYaSuscrito(t *testing.T) {
	f := &headerEvents{}
	b := headerBridge(t, f)
	if err := b.Subscribe(b.ctx, []string{"j1"}); err != nil {
		t.Fatal(err)
	}
	if !f.subscribed.Load() {
		t.Fatal("Subscribe volvió antes de que el núcleo se suscribiera al bus")
	}
}

// Un núcleo que acepta el stream pero nunca manda encabezados no deja colgado a Subscribe (ni al bucle de reconexión
// que llama a resubscribe): pasado el plazo vuelve como antes.
func TestSubscribeNoSeCuelgaSinEncabezados(t *testing.T) {
	old := headerWait
	headerWait = 100 * time.Millisecond
	defer func() { headerWait = old }()
	b := headerBridge(t, &headerEvents{silent: true})
	done := make(chan error, 1)
	go func() { done <- b.Subscribe(b.ctx, []string{"j1"}) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Subscribe se colgó esperando los encabezados")
	}
}

// Un stream que termina sin error ni encabezados queda muerto: el siguiente Subscribe lo vuelve a abrir.
func TestSubscribeStreamVacioQuedaMuerto(t *testing.T) {
	f := &headerEvents{empty: true}
	b := headerBridge(t, f)
	for i := 0; i < 2; i++ {
		if err := b.Subscribe(b.ctx, []string{"j1"}); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.opens.Load(); n != 2 {
		t.Fatalf("aperturas = %d; el stream vacío debía quedar muerto y reabrirse", n)
	}
}
