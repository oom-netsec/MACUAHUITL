package security

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Un fallo a mitad de la escritura quita solo lo que este intento creó.
func TestWriteCAFalloALaMitadLimpia(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	n := 0
	orig := writeNewFn
	defer func() { writeNewFn = orig }()
	writeNewFn = func(p string, d []byte) error {
		if n++; n == 2 {
			return errors.New("disco lleno")
		}
		return orig(p, d)
	}
	if err := writeCA(dir, []byte("c"), []byte("k")); err == nil {
		t.Fatal("debía fallar")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("quedó la carpeta: %v", err)
	}
	writeNewFn = orig
	if err := writeCA(dir, []byte("c"), []byte("k")); err != nil { // reintento
		t.Fatal(err)
	}
}
