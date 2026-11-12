package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunGeneraParVerificableYNoPisa(t *testing.T) {
	dir := t.TempDir()
	priv, pub := filepath.Join(dir, "firma", "mpack.key"), filepath.Join(dir, "pack", "oom.pub")
	if err := run(priv, pub); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(priv)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("permisos de la privada = %v, quiero 0600", st.Mode().Perm())
	}
	if err := verifica(priv, pub); err != nil {
		t.Fatal(err)
	}
	if err := run(priv, pub); err == nil {
		t.Fatal("pisó una llave existente")
	}
	otra := filepath.Join(dir, "otra.pub")
	if err := run(filepath.Join(dir, "otra.key"), otra); err != nil {
		t.Fatal(err)
	}
	if err := verifica(priv, otra); err == nil {
		t.Fatal("aceptó una pública que no es de la privada")
	}
}
