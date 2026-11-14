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

// resubscribe abre en paralelo: con un núcleo mudo las cuatro aperturas están en curso a la vez (en serie, la segunda
// esperaría el plazo entero de la primera). Sin medir el total: bajo carga solo cambia cuánto tarda en llegar a 4.
func TestResubscribeEsParalelo(t *testing.T) {
	old := headerWait
	headerWait = 3 * time.Second
	defer func() { headerWait = old }()
	f := &headerEvents{silent: true}
	b := headerBridge(t, f)
	b.mu.Lock()
	for _, id := range []string{"a", "b", "c", "d"} {
		b.streams[id] = &stream{cancel: func() {}}
	}
	b.mu.Unlock()
	done := make(chan struct{})
	go func() { b.resubscribe(); close(done) }()
	for deadline := time.Now().Add(2 * time.Second); f.opens.Load() < 4; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("aperturas en curso = %d antes del plazo; en paralelo debían ser 4", f.opens.Load())
		}
	}
	<-done
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
