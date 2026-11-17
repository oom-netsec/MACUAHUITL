package sys

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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

func TestMkdirPrivateRechazaRutasRelativas(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, p := range []string{"", "rel", "./rel"} {
		if err := MkdirPrivate(p); !errors.Is(err, fs.ErrInvalid) {
			t.Errorf("MkdirPrivate(%q) = %v", p, err)
		}
	}
	if es, _ := os.ReadDir("."); len(es) != 0 {
		t.Fatalf("creó algo en el directorio actual: %v", es)
	}
}

func TestOpenNewPrivateYCreateTempPrivateEnLinux(t *testing.T) {
	d := t.TempDir()
	f, err := OpenNewPrivate(filepath.Join(d, "a"))
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if ok, _ := IsPrivate(filepath.Join(d, "a")); !ok {
		t.Fatal("OpenNewPrivate no dejó 0600")
	}
	if _, err := OpenNewPrivate(filepath.Join(d, "a")); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("segunda vez: %v", err)
	}
	tmp, err := CreateTempPrivate(d, ".x-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	if ok, _ := IsPrivate(tmp.Name()); !ok {
		t.Fatal("CreateTempPrivate no dejó 0600")
	}
}

// ForeignWriters: el bit de grupo cuenta salvo con el grupo privado del usuario (umask 002); el de otros siempre.
func TestForeignWritersBitsDeGrupoYOtros(t *testing.T) {
	old := groupIsPrivate
	t.Cleanup(func() { groupIsPrivate = old })
	for _, c := range []struct {
		modo    os.FileMode
		privado bool
		want    []string
	}{
		{0o700, false, nil}, {0o750, false, nil}, {0o770, false, []string{"g+w"}}, {0o770, true, nil}, {0o707, true, []string{"o+w"}},
		{0o777, false, []string{"g+w", "o+w"}}, {0o777, true, []string{"o+w"}}, {0o775, false, []string{"g+w"}},
	} {
		groupIsPrivate = func(os.FileInfo) bool { return c.privado }
		d := t.TempDir()
		os.Chmod(d, c.modo)
		w, err := ForeignWriters(d)
		if err != nil || !slices.Equal(w.Who, c.want) {
			t.Errorf("%o privado=%v: %v %v, quería %v", c.modo, c.privado, w.Who, err, c.want)
		}
	}
}
