package sys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMkfifoNoSoportadoEnWindows(t *testing.T) {
	if err := Mkfifo(filepath.Join(t.TempDir(), "tubo")); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Mkfifo: %v", err)
	}
}

// Sin verificación por SID todavía (43a3): Owner falla cerrado.
func TestOwnerFallaCerradoEnWindows(t *testing.T) {
	fi, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if uid, ok := Owner(fi); ok || uid != 0 {
		t.Fatalf("Owner = %d, %v", uid, ok)
	}
}

// HardLinked por FileInfo no ve la cuenta de enlaces en Windows: decide HardLinkedFile.
func TestHardLinkedPorFileInfoEsFiltroEnWindows(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a")
	os.WriteFile(p, []byte("x"), 0o600)
	if err := os.Link(p, filepath.Join(dir, "b")); err != nil {
		t.Skip(err)
	}
	fi, _ := os.Stat(p)
	if HardLinked(fi) {
		t.Fatal("HardLinked(fi) debe devolver false en Windows")
	}
}

// En Windows RenameNoReplaceIn arma rutas absolutas: un nombre que salga de la carpeta se rechaza.
func TestRenameNoReplaceInNoSaleDeLaCarpeta(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	os.WriteFile(filepath.Join(dir, "a"), []byte("A"), 0o600)
	for _, dst := range []string{"../x", `..\x`, `C:\x`} {
		if err := RenameNoReplaceIn(root, "a", dst); err == nil {
			t.Fatalf("%q: salió de la carpeta", dst)
		}
	}
}
