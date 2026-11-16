//go:build windows

package power

import (
	"context"
	"testing"
	"time"
)

func TestInhibidorReal(t *testing.T) {
	rel, missing := NewLogind().Take("prueba")
	t.Logf("faltantes: %v", missing)
	rel()
	rel() // idempotente
}

func TestWatchCancela(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Watch(ctx, func() {}, func() {}); close(done) }()
	time.Sleep(200 * time.Millisecond)
	select {
	case <-done:
		t.Fatal("Watch volvió antes de cancelar: la ventana no se creó")
	default:
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Watch no terminó al cancelar")
	}
}
