package bridge

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
)

// Si abrir falla (NotFound), la entrada no queda en b.streams: resubscribe no la reabre para siempre.
func TestOpenFallidoNoQuedaEnStreams(t *testing.T) {
	f := &headerEvents{missing: true}
	b := headerBridge(t, f)
	if err := b.Subscribe(b.ctx, []string{"nope"}); err == nil {
		t.Fatal("Subscribe debía fallar")
	}
	b.resubscribe()
	b.resubscribe()
	if n := f.opens.Load(); n != 1 {
		t.Fatalf("aperturas = %d; quería 1", n)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.streams) != 0 {
		t.Fatalf("quedaron %d streams", len(b.streams))
	}
}

// Subscribe con varios ids intenta todos aunque el primero falle.
func TestSubscribeIntentaTodosLosIds(t *testing.T) {
	f := &headerEvents{missing: true}
	b := headerBridge(t, f)
	err := b.Subscribe(b.ctx, []string{"a", "b"})
	var be *Error
	if !errors.As(err, &be) || be.Code != codes.NotFound.String() {
		t.Fatalf("err = %v", err)
	}
	if n := f.opens.Load(); n != 2 {
		t.Fatalf("aperturas = %d; quería 2", n)
	}
}

// resubscribe abre en paralelo: con un núcleo mudo tarda ~1 plazo, no N.
func TestResubscribeEsParalelo(t *testing.T) {
	old := headerWait
	headerWait = 300 * time.Millisecond
	defer func() { headerWait = old }()
	b := headerBridge(t, &headerEvents{silent: true})
	b.mu.Lock()
	for _, id := range []string{"a", "b", "c", "d"} {
		b.streams[id] = &stream{cancel: func() {}}
	}
	b.mu.Unlock()
	t0 := time.Now()
	b.resubscribe()
	if d := time.Since(t0); d > 700*time.Millisecond {
		t.Fatalf("resubscribe tardó %v; quería ~1 plazo", d)
	}
}
