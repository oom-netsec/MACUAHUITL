package bridge

import (
	"errors"
	"strings"
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
	if !errors.As(err, &be) || be.Code != codes.NotFound.String() || be.err != nil && strings.Count(err.Error(), "no existe") != 1 {
		t.Fatalf("err = %v; quería un solo *Error con el NotFound", err)
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
	if d := time.Since(t0); d > 750*time.Millisecond { // 2,5 plazos; en serie serían 4
		t.Fatalf("resubscribe tardó %v; quería ~1 plazo", d)
	}
}

// Un error transitorio (Unavailable) deja el trabajo muerto pero registrado: resubscribe lo reabre.
func TestOpenTransitorioSeReabre(t *testing.T) {
	f := &headerEvents{failFirst: true}
	b := headerBridge(t, f)
	if err := b.Subscribe(b.ctx, []string{"j1"}); err == nil {
		t.Fatal("la primera apertura debía fallar")
	}
	b.resubscribe()
	if n := f.opens.Load(); n != 2 {
		t.Fatalf("aperturas = %d; quería 2", n)
	}
	b.mu.Lock()
	st, ok := b.streams["j1"]
	live := ok && !st.dead
	b.mu.Unlock()
	if !live {
		t.Fatal("tras reabrir el stream debía estar vivo")
	}
}
