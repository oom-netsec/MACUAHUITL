package bridge

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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

func TestWriteFileNoReemplazaLoQueNoEsArchivo(t *testing.T) {
	b := New(nil, nil)
	fifo := filepath.Join(t.TempDir(), "tubo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("sin mkfifo:", err)
	}
	var be *Error
	if err := b.WriteFile(fifo, "x", "utf8", true); !errors.As(err, &be) || be.Reason != "bridge.err.save_not_regular" {
		t.Fatalf("una FIFO no debe reemplazarse aunque haya overwrite: %v", err)
	}
	if fi, err := os.Lstat(fifo); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("la FIFO debe seguir ahí: %v", err)
	}
}

func TestWriteFileReemplazaElEnlaceNoSuDestino(t *testing.T) {
	b := New(nil, nil)
	dir := t.TempDir()
	dest := filepath.Join(dir, "destino.txt")
	if err := os.WriteFile(dest, []byte("intacto"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "enlace.csv")
	if err := os.Symlink(dest, link); err != nil {
		t.Skip("sin enlaces simbólicos:", err)
	}
	if err := b.WriteFile(link, "nuevo", "utf8", true); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("el enlace debe quedar como archivo regular: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "intacto" {
		t.Fatalf("el destino del enlace no se toca: %q", got)
	}
}
