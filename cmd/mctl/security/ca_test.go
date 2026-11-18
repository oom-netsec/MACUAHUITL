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

// Una carpeta con un archivo ajeno no se borra (mata la mutación RemoveAll en vez de Remove).
func TestWriteCAFalloNoBorraAjenos(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ca")
	n := 0
	orig := writeNewFn
	defer func() { writeNewFn = orig }()
	writeNewFn = func(p string, d []byte) error {
		if n++; n == 2 {
			os.WriteFile(filepath.Join(dir, "ajeno.txt"), []byte("x"), 0o600)
			return errors.New("disco lleno")
		}
		return orig(p, d)
	}
	if err := writeCA(dir, []byte("c"), []byte("k")); err == nil {
		t.Fatal("debía fallar")
	}
	if _, err := os.Stat(filepath.Join(dir, "ajeno.txt")); err != nil {
		t.Fatalf("se borró el ajeno: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ca.crt.pem")); !os.IsNotExist(err) {
		t.Fatalf("el archivo propio debía quitarse: %v", err)
	}
}
