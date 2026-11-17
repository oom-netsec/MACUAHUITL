package field

import (
	"os"
	"path/filepath"
	"runtime"
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

// M1: la carpeta de salidas (ya validada por CheckOutputs) se cambia por un enlace a una carpeta compartida antes de abrir el archivo:
// outFile valida lo abierto y se niega.
func TestOutFileSalidasCambiadasPorEnlaceACarpetaCompartida(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0777: bits POSIX (la versión de Windows está en outfile_toctou_windows_test.go)")
	}
	d := servicetest.New(t)
	s := &fieldSvc{d: d}
	compartida := t.TempDir()
	os.Chmod(compartida, 0o777)
	os.RemoveAll(d.Outputs())
	if err := os.Symlink(compartida, d.Outputs()); err != nil {
		t.Skipf("sin enlaces simbólicos: %v", err)
	}
	if f, err := s.outFile("console", "console_x"); err == nil {
		f.Close()
		t.Fatalf("debía rechazar la carpeta compartida, creó %s", f.Name())
	}
	if es, _ := os.ReadDir(compartida); len(es) != 0 {
		t.Fatalf("escribió en la carpeta compartida: %v", es)
	}
}
