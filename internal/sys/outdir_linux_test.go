package sys

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// M1: la carpeta se cambia por un enlace a otra DESPUÉS de validarla; OpenOutDir valida lo abierto y rechaza la ajena o compartida,
// y acepta un enlace cuyo destino es propio y privado.
func TestOpenOutDirValidaLoAbiertoTrasElCambio(t *testing.T) {
	base := t.TempDir()
	salidas := filepath.Join(base, "salidas")
	if r, err := OpenOutDir(salidas); err != nil { // lo que CheckOutputs ya dio por bueno
		t.Fatal(err)
	} else {
		r.Close()
	}
	compartida := filepath.Join(base, "compartida")
	os.Mkdir(compartida, 0o700)
	os.Chmod(compartida, 0o777)
	os.Remove(salidas)
	if err := os.Symlink(compartida, salidas); err != nil {
		t.Skipf("sin enlaces simbólicos: %v", err)
	}
	r, err := OpenOutDir(salidas)
	var e *i18n.Error
	if err == nil || !errors.As(err, &e) || e.Code != "sys.err.outdir_shared" {
		if r != nil {
			r.Close()
		}
		t.Fatalf("debía rechazar la carpeta compartida: %v", err)
	}
	propia := filepath.Join(base, "propia")
	os.Mkdir(propia, 0o700)
	os.Remove(salidas)
	os.Symlink(propia, salidas)
	r, err = OpenOutDir(salidas)
	if err != nil {
		t.Fatalf("un enlace a una carpeta propia y privada se acepta: %v", err)
	}
	r.Close()
	// dueño ajeno
	oldE := geteuid
	geteuid = func() uint32 { return oldE() + 1 }
	t.Cleanup(func() { geteuid = oldE })
	if r, err := OpenOutDir(salidas); err == nil {
		r.Close()
		t.Fatal("una carpeta de otro dueño se rechaza")
	}
}
