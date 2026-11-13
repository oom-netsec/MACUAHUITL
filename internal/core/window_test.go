package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

// El plazo de un equipo es el fin de la ventana (until): Schedule.Until no lo recorta, y un equipo que
// arranca tras el fin nace vencido con window_ended.
func TestWindowCtx(t *testing.T) {
	now := time.Now()
	ctx, cancel := windowCtx(context.Background(), now.Add(time.Hour), now)
	defer cancel()
	if dl, _ := ctx.Deadline(); dl.Sub(now) < 59*time.Minute {
		t.Fatalf("plazo %s: debía ser la ventana completa", dl.Sub(now))
	}
	ctx2, cancel2 := windowCtx(context.Background(), now.Add(-time.Second), now)
	defer cancel2()
	if ctx2.Err() == nil || !errors.Is(context.Cause(ctx2), patrol.ErrWindowEnded) {
		t.Fatalf("debía nacer vencido: %v %v", ctx2.Err(), context.Cause(ctx2))
	}
}
