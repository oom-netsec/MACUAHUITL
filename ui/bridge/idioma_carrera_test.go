package bridge

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// lentoCore lee ui.language con el valor viejo y lo entrega solo cuando se le libera.
type lentoCore struct {
	v1.UnimplementedPrefsServiceServer
	v1.UnimplementedVaultServiceServer
	mu      sync.Mutex
	lang    string
	entered chan struct{}
	release chan struct{}
}

func (f *lentoCore) GetPreference(context.Context, *v1.GetPreferenceRequest) (*v1.GetPreferenceResponse, error) {
	f.mu.Lock()
	v := f.lang
	f.mu.Unlock()
	if f.entered != nil {
		f.entered <- struct{}{}
		<-f.release
	}
	return &v1.GetPreferenceResponse{Value: v, Found: v != ""}, nil
}

func (f *lentoCore) SetPreference(_ context.Context, r *v1.SetPreferenceRequest) (*v1.SetPreferenceResponse, error) {
	f.mu.Lock()
	f.lang = r.Value
	f.mu.Unlock()
	return &v1.SetPreferenceResponse{}, nil
}

func (f *lentoCore) Status(context.Context, *v1.StatusRequest) (*v1.StatusResponse, error) {
	return &v1.StatusResponse{}, nil
}

func (f *lentoCore) get() string { f.mu.Lock(); defer f.mu.Unlock(); return f.lang }

func servir(t *testing.T, f *lentoCore) string {
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

// Una lectura lenta del idioma viejo no pisa el idioma que la UI eligió mientras tanto.
func TestLecturaLentaNoPisaElIdiomaElegido(t *testing.T) {
	f := &lentoCore{lang: "es", entered: make(chan struct{}), release: make(chan struct{})}
	sock := servir(t, f)
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, func(string, any) {})
	b.Localize = true
	got := make(chan string, 1)
	go func() { got <- b.language() }()
	<-f.entered // la lectura vieja ya está en el núcleo
	f.entered = nil
	b.setLanguage("en")
	f.release <- struct{}{}
	if v := <-got; v != "en" {
		t.Fatalf("la lectura devolvió %q", v)
	}
	if v := b.language(); v != "en" {
		t.Fatalf("el puente quedó en %q", v)
	}
}

// Con el núcleo caído, el idioma elegido rige de inmediato y se sincroniza al reconectar.
func TestIdiomaElegidoSinNucleoSeAdoptaYSeSincroniza(t *testing.T) {
	f := &lentoCore{lang: "es"}
	sock := servir(t, f)
	var up atomic.Bool
	b := New(func() (*ipc.ClientConn, error) {
		if !up.Load() {
			return nil, ErrDisconnected
		}
		return ipc.DialPath(sock)
	}, func(string, any) {})
	b.Localize = true
	b.Interval = 20 * time.Millisecond
	if err := b.SetPreference("ui.language", "en"); err == nil {
		t.Fatal("debía fallar sin núcleo")
	}
	if v := b.language(); v != "en" {
		t.Fatalf("idioma %q", v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	Start(ctx, b)
	up.Store(true)
	for i := 0; i < 100 && f.get() != "en"; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if f.get() != "en" {
		t.Fatalf("el núcleo quedó con %q", f.get())
	}
}
