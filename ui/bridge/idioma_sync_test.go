package bridge

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// lentoSet retiene el primer SetPreference hasta que se libera; los demás pasan.
type lentoSet struct {
	*lentoCore
	first   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (f *lentoSet) SetPreference(ctx context.Context, r *v1.SetPreferenceRequest) (*v1.SetPreferenceResponse, error) {
	if f.first.CompareAndSwap(false, true) {
		f.entered <- struct{}{}
		<-f.release
	}
	return f.lentoCore.SetPreference(ctx, r)
}

// Si la UI elige Y mientras se manda el X pendiente, el núcleo no se queda con X.
func TestSyncLanguageNoDejaElIdiomaViejo(t *testing.T) {
	core := &lentoCore{}
	f := &lentoSet{lentoCore: core, entered: make(chan struct{}), release: make(chan struct{})}
	sock2 := servirSet(t, f)
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock2) }, func(string, any) {})
	b.Localize = true
	b.setLanguage("es")
	b.lang.mu.Lock()
	b.lang.pending = "es"
	b.lang.mu.Unlock()
	c, err := b.client()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { b.syncLanguage(c); close(done) }()
	<-f.entered
	if err := b.SetPreference("ui.language", "en"); err != nil {
		t.Fatal(err)
	}
	f.release <- struct{}{}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("syncLanguage no terminó")
	}
	if v := core.get(); v != "en" {
		t.Fatalf("el núcleo quedó con %q", v)
	}
}

func servirSet(t *testing.T, f *lentoSet) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "core.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ipc.Serve(ctx, l, func(r ipc.Registrar) {
		v1.RegisterPrefsServiceServer(r, f)
		v1.RegisterVaultServiceServer(r, f)
	}, ipc.LocaleOptions()...)
	return sock
}
