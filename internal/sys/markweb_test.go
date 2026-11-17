package sys

import (
	"os"
	"path/filepath"
	"testing"
)

// En todos los sistemas marcar no rompe ni cambia el archivo (en Linux es un no-op).
func TestMarkOfTheWebNoTocaElContenido(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.bin")
	os.WriteFile(p, []byte("x"), 0o600)
	MarkOfTheWeb(p)
	if b, _ := os.ReadFile(p); string(b) != "x" {
		t.Fatalf("contenido = %q", b)
	}
}
