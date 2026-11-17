package diag

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// 2.1 (POSIBLE BUG 7): la carpeta de salidas validada se cambia por un enlace DESPUÉS de abrirla. El archivo debe quedar en la
// carpeta original (la que se abrió), no en la que el atacante puso en su lugar.
func TestRunSalidaCambiadaPorEnlaceTrasAbrirNoDesvia(t *testing.T) {
	localTest(t)
	base := t.TempDir()
	salidas, atacante := filepath.Join(base, "salidas"), filepath.Join(base, "atacante")
	os.Mkdir(salidas, 0o700)
	os.Mkdir(atacante, 0o700)
	movida := filepath.Join(base, "movida")
	afterOutDirOpen = func() {
		os.Rename(salidas, movida)
		os.Symlink(atacante, salidas)
	}
	t.Cleanup(func() { afterOutDirOpen = func() {} })
	res, err := runner(t).Run(context.Background(), Request{Tool: Ping, Targets: []string{"192.0.2.1"}, OutputDir: salidas}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if es, _ := os.ReadDir(atacante); len(es) != 0 {
		t.Fatalf("el archivo cayó en la carpeta del atacante: %v", es)
	}
	if es, _ := os.ReadDir(movida); len(es) != 1 {
		t.Fatalf("el archivo debía quedar en la carpeta original: %v", es)
	}
	if res.OutputPath == "" || filepath.Dir(res.OutputPath) != salidas {
		t.Fatalf("OutputPath = %q", res.OutputPath)
	}
}

// El archivo de salida nace 0600, es regular y lleva el nombre diag_<herramienta>_<hora>_<n>.txt.
func TestRunSalidaNaceRegularYPrivada(t *testing.T) {
	localTest(t)
	d := t.TempDir()
	res, err := runner(t).Run(context.Background(), Request{Tool: Ping, Targets: []string{"192.0.2.1"}, OutputDir: d}, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(res.OutputPath)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 || filepath.Dir(res.OutputPath) != d {
		t.Fatalf("%v %v", fi, err)
	}
}
