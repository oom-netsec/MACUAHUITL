package bridge

import (
	"context"
	"strings"

	"errors"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// Con Localize y el idioma sin precargar, un dial que falla no debe colgar el puente (lang.mu + client + disconnected).
func TestIdiomaSinNucleoNoSeCuelga(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "core.sock") // sin servidor al principio
	up := false
	b := New(func() (*ipc.ClientConn, error) {
		if !up {
			return nil, errors.New("sin núcleo")
		}
		return ipc.DialPath(sock)
	}, func(string, any) {})
	b.Localize = true
	done := make(chan error, 1)
	go func() { done <- b.WriteFile("rel", "x", "utf8", false) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("debía fallar")
		}
	case <-time.After(time.Second):
		t.Fatal("interbloqueo: la llamada no volvió")
	}
	// Una segunda llamada tampoco se cuelga (el candado quedó libre).
	go func() { done <- b.WriteFile("rel", "x", "utf8", false) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sigue colgado")
	}
	// Al levantarse el núcleo, el puente se recupera: lee el idioma y responde en en.
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := &i18nCore{lang: "en"}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterPrefsServiceServer(r, f) }, ipc.LocaleOptions()...)
	up = true
	if err := b.WriteFile("rel", "x", "utf8", false); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("sin recuperar el idioma: %v", err)
	}
}
