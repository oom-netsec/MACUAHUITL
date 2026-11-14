package bridge

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

func TestWriteFile(t *testing.T) {
	b := New(nil, nil)
	dir := t.TempDir()
	p := filepath.Join(dir, "cpu.csv")
	if err := b.WriteFile(p, "hora,cpu\n", "utf8", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) != "hora,cpu\n" {
		t.Fatalf("contenido: %q", got)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("permisos: %v", fi.Mode().Perm())
	}
	png := filepath.Join(dir, "g.png")
	if err := b.WriteFile(png, "UE5H", "base64", false); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(png); string(got) != "PNG" {
		t.Fatalf("base64: %q", got)
	}
	// Sin permiso explícito no sobrescribe (el diálogo GTK3 de Wails no lo confirma); con él, reemplaza entero.
	if err := b.WriteFile(p, "otro", "utf8", false); !errors.Is(err, ErrFileExists) {
		t.Fatalf("sobrescribió sin permiso: %v", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "hora,cpu\n" {
		t.Fatalf("el original cambió: %q", got)
	}
	if err := b.WriteFile(p, "nuevo", "utf8", true); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) != "nuevo" {
		t.Fatalf("no reemplazó: %q", got)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("quedaron temporales: %v", ents)
	}
	for _, c := range []struct{ path, data, enc, want string }{
		{"relativa.txt", "x", "utf8", "absoluta"},
		{filepath.Join(dir, "a.txt"), "x", "latin1", "codificación"},
		{filepath.Join(dir, "b.png"), "%%%", "base64", "base64"},
		{filepath.Join(dir, "no", "existe.txt"), "x", "utf8", "no such file"},
		{filepath.Join(dir, "grande.txt"), strings.Repeat("x", maxSaveBytes+1), "utf8", "64 MiB"},
	} {
		if err := b.WriteFile(c.path, c.data, c.enc, false); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, se esperaba %q", c.path, err, c.want)
		}
	}
}

// Un archivo creado entre la comprobación y el renombrado no se reemplaza si no se pidió overwrite.
func TestWriteFileCarreraNoReemplaza(t *testing.T) {
	b := New(nil, func(string, any) {})
	p := filepath.Join(t.TempDir(), "x.csv")
	beforeSaveRename = func() { os.WriteFile(p, []byte("ajeno"), 0o600) }
	defer func() { beforeSaveRename = nil }()
	if err := b.WriteFile(p, "mio", "utf8", false); !errors.Is(err, ErrFileExists) {
		t.Fatalf("err = %v; quería ErrFileExists", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "ajeno" {
		t.Fatalf("el archivo ajeno quedó con %q", got)
	}
}

// En sistemas de archivos sin enlaces duros ni RENAME_NOREPLACE (CIFS, FUSE) se cae a Lstat + Rename.
func TestWriteFileSinLinkNiNoReplace(t *testing.T) {
	b := New(nil, func(string, any) {})
	oldL, oldR := linkFile, renameNoReplace
	linkFile = func(string, string) error { return &os.LinkError{Op: "link", Err: sys.ErrNoAtomicRename} }
	renameNoReplace = func(*os.Root, string, string) error { return sys.ErrNoAtomicRename }
	defer func() { linkFile, renameNoReplace = oldL, oldR }()
	p := filepath.Join(t.TempDir(), "x.csv")
	if err := b.WriteFile(p, "mio", "utf8", false); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "mio" {
		t.Fatalf("contenido %q", got)
	}
	if err := b.WriteFile(p, "otro", "utf8", false); !errors.Is(err, ErrFileExists) {
		t.Fatalf("err = %v; quería ErrFileExists", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "mio" {
		t.Fatalf("se reemplazó: %q", got)
	}
}
