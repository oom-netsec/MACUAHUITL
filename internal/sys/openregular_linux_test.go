//go:build linux

package sys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOpenRegularFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "tubo")
	if err := Mkfifo(fifo); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := OpenRegular(fifo); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Fatalf("FIFO: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("OpenRegular se colgó con una FIFO")
	}
}

func TestOpenInRootLinux(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := OpenNewIn(root, "nuevo")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if st, _ := os.Stat(filepath.Join(dir, "nuevo")); st == nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("permisos: %v", st)
	}
	Mkfifo(filepath.Join(dir, "tuberia"))
	if _, err := OpenRegularIn(root, "tuberia"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("FIFO: %v", err)
	}
	// Enlaces duros por FileInfo (Nlink).
	fi, _ := os.Stat(filepath.Join(dir, "nuevo"))
	if HardLinked(fi) {
		t.Fatal("Nlink 1 marcado como enlace duro")
	}
	os.Link(filepath.Join(dir, "nuevo"), filepath.Join(dir, "duro"))
	fi, _ = os.Stat(filepath.Join(dir, "nuevo"))
	if !HardLinked(fi) {
		t.Fatal("Nlink 2 no se detectó")
	}
}

func TestOwner(t *testing.T) {
	fi, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if uid, ok := Owner(fi); !ok || uid != uint32(os.Getuid()) {
		t.Fatalf("dueño = %d, %v; quería %d", uid, ok, os.Getuid())
	}
}
