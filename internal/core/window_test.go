package core

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

// El plazo de un equipo es el fin de la ventana (until): Schedule.Until no lo recorta, y un equipo que
// arranca tras el fin nace vencido con window_ended.
func TestWindowCtx(t *testing.T) {
	now := time.Now()
	ctx, cancel := windowCtx(context.Background(), now.Add(time.Hour), func() time.Time { return now })
	defer cancel()
	if dl, _ := ctx.Deadline(); dl.Sub(now) < 59*time.Minute {
		t.Fatalf("plazo %s: debía ser la ventana completa", dl.Sub(now))
	}
	ctx2, cancel2 := windowCtx(context.Background(), now.Add(-time.Second), func() time.Time { return now })
	defer cancel2()
	if ctx2.Err() == nil || !errors.Is(context.Cause(ctx2), patrol.ErrWindowEnded) {
		t.Fatalf("debía nacer vencido: %v %v", ctx2.Err(), context.Cause(ctx2))
	}
}

// Si el sistema se suspende con un equipo a mitad de ronda, el temporizador monotónico se alarga lo que dure la
// suspensión: el vigilante de hora de pared cancela con window_ended en cuanto pasa el fin de la ventana.
func TestWindowCtxVigilaLaHoraDePared(t *testing.T) {
	old := windowTick
	windowTick = 5 * time.Millisecond
	t.Cleanup(func() { windowTick = old })
	var ns atomic.Int64
	ns.Store(time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC).UnixNano())
	now := func() time.Time { return time.Unix(0, ns.Load()).UTC() }
	ctx, cancel := windowCtx(context.Background(), now().Add(time.Hour), now)
	defer cancel()
	ns.Add(int64(2 * time.Hour)) // salto de pared sin avance monotónico
	select {
	case <-ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("el contexto no se canceló al pasar la ventana")
	}
	if !errors.Is(context.Cause(ctx), patrol.ErrWindowEnded) {
		t.Fatalf("causa = %v", context.Cause(ctx))
	}
	// Sin fuga: cancelar el contexto termina al vigilante.
	before := runtime.NumGoroutine()
	for range 20 {
		c, cn := windowCtx(context.Background(), now().Add(time.Hour), now)
		cn()
		<-c.Done()
	}
	time.Sleep(100 * time.Millisecond)
	if n := runtime.NumGoroutine(); n > before+2 {
		t.Fatalf("goroutines: %d -> %d", before, n)
	}
}

// El fin de la ventana de un trabajo armado con el reloj real no lleva lectura monotónica.
func TestVentanaDelTrabajoSinLecturaMonotonica(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.arm(t, cred)
	h.core.mu.Lock()
	u := h.core.jobs[job].Until
	h.core.mu.Unlock()
	if u.IsZero() || strings.Contains(u.String(), "m=") {
		t.Fatalf("j.Until = %v", u)
	}
	h.waitJob(t, job, "closed")
}
