package systest

import (
	"os"
	"path/filepath"
	"testing"
)

type fakeT struct {
	testing.TB
	failed bool
}

func (f *fakeT) Helper()               {}
func (f *fakeT) Errorf(string, ...any) { f.failed = true }

func TestPrivateYInheritedEnLinux(t *testing.T) {
	d := t.TempDir()
	f := filepath.Join(d, "x")
	os.WriteFile(f, nil, 0o600)
	if ft := (&fakeT{}); func() bool { Private(ft, f, 0o600); return ft.failed }() {
		t.Fatal("0600 debía pasar")
	}
	os.Chmod(f, 0o644)
	for _, fn := range []func(testing.TB, string, os.FileMode){Private, Inherited} {
		ft := &fakeT{}
		fn(ft, f, 0o600)
		if !ft.failed {
			t.Fatal("0644 debía fallar")
		}
	}
}
