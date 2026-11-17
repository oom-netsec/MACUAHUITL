package sys

import (
	"os"
	"path/filepath"
	"testing"
)

// OpenOutDir: el archivo nace dentro de la carpeta abierta aunque después se cambie por un enlace; sigue los enlaces de la
// ruta al abrir (la carpeta de fábrica puede ser uno).
func TestOpenOutDirYCreateTempIn(t *testing.T) {
	base := t.TempDir()
	real, enlace, atacante := filepath.Join(base, "real"), filepath.Join(base, "enlace"), filepath.Join(base, "atacante")
	os.Mkdir(real, 0o700)
	os.Mkdir(atacante, 0o700)
	if err := os.Symlink(real, enlace); err != nil {
		t.Skipf("sin enlaces simbólicos: %v", err)
	}
	root, err := OpenOutDir(enlace)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	movida := filepath.Join(base, "movida")
	if err := os.Rename(real, movida); err != nil {
		movida = real // Windows no deja mover una carpeta con un handle abierto: ahí la carrera no existe
	} else {
		os.Symlink(atacante, real) // cambiada tras abrir
	}
	f, err := CreateTempIn(root, "x_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	if es, _ := os.ReadDir(atacante); len(es) != 0 {
		t.Fatalf("cayó en la carpeta del atacante: %v", es)
	}
	if es, _ := os.ReadDir(movida); len(es) != 1 {
		t.Fatalf("debía quedar en la carpeta abierta: %v", es)
	}
	// crea la carpeta si falta
	if r2, err := OpenOutDir(filepath.Join(base, "nueva", "sub")); err != nil {
		t.Fatal(err)
	} else {
		r2.Close()
	}
}

// MkdirOpenIn no sigue un enlace que salga de la carpeta abierta.
func TestMkdirOpenInRechazaEnlaceHaciaFuera(t *testing.T) {
	base, fuera := t.TempDir(), t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Symlink(fuera, filepath.Join(base, "sub")); err != nil {
		t.Skipf("sin enlaces simbólicos: %v", err)
	}
	if r, err := MkdirOpenIn(root, "sub"); err == nil {
		r.Close()
		t.Fatal("debía rechazar el enlace hacia fuera")
	}
}
