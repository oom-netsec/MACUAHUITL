package security

import (
	"os"
	"path/filepath"
	"testing"
)

// Un fallo real de escritura (el archivo ya está cerrado) no deja el archivo a medias.
func TestFillFalloRealQuitaArchivo(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.pem")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := fill(f, p, []byte("datos")); err == nil {
		t.Fatal("debía fallar")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("quedó el archivo: %v", err)
	}
}
