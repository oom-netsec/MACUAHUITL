package bridge

import (
	"cmp"
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakePrefs struct {
	v1.UnimplementedPrefsServiceServer
	m    map[string]string
	core *v1.CorePrefs
}

func (f *fakePrefs) state() *v1.CorePrefsState {
	return &v1.CorePrefsState{Prefs: f.core, OutputsDirEffective: cmp.Or(f.core.OutputsDir, "/fabrica"), OutputsDirDefault: "/fabrica"}
}

func (f *fakePrefs) GetCorePrefs(context.Context, *v1.GetCorePrefsRequest) (*v1.GetCorePrefsResponse, error) {
	return &v1.GetCorePrefsResponse{State: f.state()}, nil
}

func (f *fakePrefs) SetCorePrefs(_ context.Context, r *v1.SetCorePrefsRequest) (*v1.SetCorePrefsResponse, error) {
	f.core = r.Prefs
	st := f.state()
	st.Note = "aviso"
	return &v1.SetCorePrefsResponse{State: st}, nil
}

func (f *fakePrefs) GetPreference(_ context.Context, r *v1.GetPreferenceRequest) (*v1.GetPreferenceResponse, error) {
	v, ok := f.m[r.Key]
	return &v1.GetPreferenceResponse{Value: v, Found: ok}, nil
}

func (f *fakePrefs) SetPreference(_ context.Context, r *v1.SetPreferenceRequest) (*v1.SetPreferenceResponse, error) {
	f.m[r.Key] = r.Value
	return &v1.SetPreferenceResponse{}, nil
}

func TestPreferencesBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) {
		v1.RegisterPrefsServiceServer(r, &fakePrefs{m: map[string]string{}, core: &v1.CorePrefs{}})
	})
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	if v, err := b.GetPreference("terminal"); err != nil || v != "" {
		t.Fatal(v, err)
	}
	if err := b.SetPreference("terminal", `{"palette":"p3"}`); err != nil {
		t.Fatal(err)
	}
	if v, _ := b.GetPreference("terminal"); v != `{"palette":"p3"}` {
		t.Fatal(v)
	}
}

func TestCorePrefsBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) {
		v1.RegisterPrefsServiceServer(r, &fakePrefs{m: map[string]string{}, core: &v1.CorePrefs{}})
	})
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	g, err := b.GetCorePrefs()
	if err != nil || g.OutputsDir != "" || g.OutputsDirEffective != "/fabrica" || g.OutputsDirDefault != "/fabrica" {
		t.Fatalf("get %+v %v", g, err)
	}
	s, err := b.SetCorePrefs(CorePrefsDTO{OutputsDir: "/x", RotateMB: 10, RotateMin: 5, MaxFiles: 7, Format: "jsonl"})
	if err != nil || s.OutputsDir != "/x" || s.OutputsDirEffective != "/x" || s.RotateMB != 10 || s.RotateMin != 5 || s.MaxFiles != 7 || s.Format != "jsonl" || s.Note != "aviso" {
		t.Fatalf("set %+v %v", s, err)
	}
	if g, _ = b.GetCorePrefs(); g.MaxFiles != 7 || g.Format != "jsonl" {
		t.Fatalf("get tras set %+v", g)
	}
}
