package sys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivadasEnLinux(t *testing.T) {
	d := filepath.Join(t.TempDir(), "a", "b")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o700 {
		t.Fatalf("MkdirPrivate dejó %v", fi.Mode().Perm())
	}
	f := filepath.Join(d, "x")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, _ := IsPrivate(f); ok {
		t.Fatal("0644 no es privado")
	}
	if err := ProtectFile(f); err != nil {
		t.Fatal(err)
	}
	if ok, err := IsPrivate(f); !ok || err != nil {
		t.Fatalf("IsPrivate = %v, %v", ok, err)
	}
}

func TestPrivateDirEnLinux(t *testing.T) {
	var pe *PrivateDirError
	t.Setenv("TMPDIR", os.Getenv("HOME")) // /tmp es 1777 y de otro dueño: contaría como ancestro inseguro
	d := filepath.Join(t.TempDir(), "o")
	if err := os.Mkdir(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(d); !errors.As(err, &pe) || pe.Reason != PrivateDirACL {
		t.Fatalf("0755: %v", err)
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := PrivateDir(d); err != nil {
		t.Fatalf("0700 propia: %v", err)
	}
	if err := PrivateDir(filepath.Join(d, "no")); !errors.As(err, &pe) || pe.Reason != PrivateDirRead {
		t.Fatalf("inexistente: %v", err)
	}
	// /tmp es de otro dueño y 1777: una carpeta suya directo en /tmp se rechaza por ancestro.
	t1, err := os.MkdirTemp("/tmp", "mcw-")
	if err != nil {
		t.Skip(err)
	}
	defer os.RemoveAll(t1)
	if err := PrivateDir(t1); !errors.As(err, &pe) || pe.Reason != PrivateDirAncestor || pe.Path != "/tmp" {
		t.Fatalf("bajo /tmp: %v", err)
	}
}

// ProtectNew no toca el modo en Linux: el archivo ya nació 0600 y un sistema sin permisos no debe fallar.
func TestProtectNewNoHaceNadaEnLinux(t *testing.T) {
	f := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(f, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	os.Chmod(f, 0o640)
	if err := ProtectNew(f); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o640 {
		t.Fatalf("modo %v", fi.Mode().Perm())
	}
}

func TestReadOnlyDirEnLinux(t *testing.T) {
	d := t.TempDir()
	antes, _ := os.Stat(d)
	restore, err := ReadOnlyDir(d)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(d); fi.Mode().Perm() != 0o500 {
		t.Fatalf("modo %v", fi.Mode().Perm())
	}
	restore()
	if fi, _ := os.Stat(d); fi.Mode().Perm() != antes.Mode().Perm() {
		t.Fatalf("restaurado %v", fi.Mode().Perm())
	}
}
