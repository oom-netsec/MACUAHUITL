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

func TestRunRechazaPrivadaDentroDelDirectorioDeTrabajo(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, p := range []string{"mpack.key", "~/.config/x/mpack.key", filepath.Join(dir, "sub", "mpack.key")} {
		if err := run(p, filepath.Join(t.TempDir(), "oom.pub")); err == nil {
			t.Fatalf("aceptó -priv %q dentro del directorio de trabajo", p)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("dejó archivos en el directorio de trabajo: %v", entries)
	}
}

func TestRunNoDejaPrivadaSiLaPublicaNoSePuede(t *testing.T) {
	dir := t.TempDir()
	bloqueo := filepath.Join(dir, "archivo")
	if err := os.WriteFile(bloqueo, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	priv := filepath.Join(dir, "firma", "mpack.key")
	if err := run(priv, filepath.Join(bloqueo, "oom.pub")); err == nil {
		t.Fatal("no falló con el padre de la pública siendo un archivo")
	}
	if _, err := os.Stat(priv); !os.IsNotExist(err) {
		t.Fatal("quedó una privada huérfana")
	}
}
