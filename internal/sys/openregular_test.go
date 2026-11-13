package sys

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestOpenRegular(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "a")
	os.WriteFile(reg, []byte("x"), 0o600)
	f, err := OpenRegular(reg)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := OpenRegular(dir); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("directorio: %v", err)
	}
	if _, err := OpenRegular(filepath.Join(dir, "no")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inexistente: %v", err)
	}
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

func TestOpenInRoot(t *testing.T) {
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
	f.Write([]byte("hola"))
	f.Close()
	if st, _ := os.Stat(filepath.Join(dir, "nuevo")); st == nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("permisos: %v", st)
	}
	if _, err := OpenNewIn(root, "nuevo"); !errors.Is(err, os.ErrExist) {
		t.Fatalf("sobrescribió: %v", err)
	}
	if _, err := OpenNewIn(root, "../fuera"); err == nil {
		t.Fatal("salió de la carpeta")
	}
	os.Symlink("/etc/hostname", filepath.Join(dir, "enlace"))
	if _, err := OpenNewIn(root, "enlace"); err == nil {
		t.Fatal("siguió un enlace")
	}
	g, err := OpenRegularIn(root, "nuevo")
	if err != nil {
		t.Fatal(err)
	}
	g.Close()
	Mkfifo(filepath.Join(dir, "tuberia"))
	if _, err := OpenRegularIn(root, "tuberia"); !errors.Is(err, ErrNotRegular) {
		t.Fatalf("FIFO: %v", err)
	}
	// Enlaces duros.
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

// Fase 30d: ErrNotRegular lleva código; el texto en español es el de siempre y con en sale en inglés.
func TestErrNotRegularEsYEn(t *testing.T) {
	if ErrNotRegular.Error() != "la ruta no es un archivo regular" {
		t.Errorf("es: %q", ErrNotRegular.Error())
	}
	if en := i18n.In("en", fmt.Errorf("abrir: %w", ErrNotRegular)); en != "abrir: the path is not a regular file" {
		t.Errorf("en: %q", en)
	}
}
