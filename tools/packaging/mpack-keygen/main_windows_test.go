package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Otra forma del mismo volumen (\\?\C:\…) hace fallar filepath.Rel igual que otra unidad: no debe colarse dentro del repo.
func TestRutaDelMismoVolumenEnOtraFormaSeRechaza(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	priv := `\\?\` + filepath.Join(cwd, "fuga.key")
	if err := run(priv, filepath.Join(t.TempDir(), "oom.pub")); err == nil {
		os.Remove(filepath.Join(cwd, "fuga.key"))
		t.Fatalf("aceptó %s, que está dentro del directorio de trabajo", priv)
	}
}
