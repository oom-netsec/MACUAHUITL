package field

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// 2.1 (POSIBLE BUG 7): la subcarpeta de salidas de Field cambiada por un enlace hacia fuera de la carpeta de salidas. El archivo
// no debe caer afuera. Se abre la carpeta de salidas una vez y la subcarpeta va por ese handle (os.Root no sigue enlaces que salgan).
func TestOutFileSubcarpetaEnlazadaAFueraNoEscribeAfuera(t *testing.T) {
	d := servicetest.New(t)
	s := &fieldSvc{d: d}
	fuera := t.TempDir()
	os.MkdirAll(d.Outputs(), 0o700)
	if err := os.Symlink(fuera, filepath.Join(d.Outputs(), "console")); err != nil {
		t.Skipf("sin enlaces simbólicos: %v", err)
	}
	f, err := s.outFile("console", "console_ttyUSB0")
	if err == nil {
		f.Close()
		t.Fatalf("debía rechazar la subcarpeta enlazada hacia fuera, creó %s", f.Name())
	}
	if es, _ := os.ReadDir(fuera); len(es) != 0 {
		t.Fatalf("escribió fuera de la carpeta de salidas: %v", es)
	}
}

// Un enlace hacia otra carpeta DENTRO de las salidas sí se acepta (os.Root solo bloquea lo que sale), y el archivo nuevo queda
// donde la ruta del enlace dice.
func TestOutFileCreaLaSubcarpetaYElArchivoQuedaDentro(t *testing.T) {
	d := servicetest.New(t)
	s := &fieldSvc{d: d}
	f, err := s.outFile("console", "console_x")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if want := filepath.Join(d.Outputs(), "console"); filepath.Dir(f.Name()) != want {
		t.Fatalf("Name = %s, quería dentro de %s", f.Name(), want)
	}
}
