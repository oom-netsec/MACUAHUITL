package sys

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	if err == nil || !errors.As(err, &e) || e.Code != "sys.err.outdir_shared_cmd" || !strings.Contains(e.Localize(i18n.En), "chmod o-w") {
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

// El error trae la orden que lo arregla y ningún texto crudo («owner», «g+w») en ningún idioma; sin orden si la ruta no es segura,
// si el dueño es ajeno o si el volumen no admite chmod (ahí pide remontar).
func TestOpenOutDirMensajes(t *testing.T) {
	crudo := func(err error) {
		t.Helper()
		for _, loc := range []string{i18n.Es, i18n.En} {
			m := i18n.In(loc, err)
			if loc == i18n.Es && strings.Contains(m, "owner") || strings.Contains(m, "g+w") || strings.Contains(m, "o+w") {
				t.Errorf("%s: texto crudo: %s", loc, m)
			}
		}
	}
	base := t.TempDir()
	abrir := func(dir string) error {
		r, err := OpenOutDir(dir)
		if err == nil {
			r.Close()
		}
		return err
	}
	seguro := filepath.Join(base, "a")
	os.Mkdir(seguro, 0o700)
	os.Chmod(seguro, 0o777)
	err := abrir(seguro)
	crudo(err)
	if m := i18n.In(i18n.Es, err); !strings.Contains(m, "chmod o-w "+seguro) || !strings.Contains(m, "escritura para otros usuarios") {
		t.Errorf("sin orden o sin texto en español: %v", m)
	}
	conEspacio := filepath.Join(base, "con espacio")
	os.Mkdir(conEspacio, 0o700)
	os.Chmod(conEspacio, 0o777)
	if err := abrir(conEspacio); err == nil || strings.Contains(i18n.In(i18n.En, err), "chmod") {
		t.Errorf("ruta no segura: sin orden: %v", err)
	}
	old := geteuid
	geteuid = func() uint32 { return old() + 1 }
	t.Cleanup(func() { geteuid = old })
	err = abrir(seguro)
	crudo(err)
	if strings.Contains(i18n.In(i18n.En, err), "chmod") || !strings.Contains(i18n.In(i18n.En, err), "another owner") {
		t.Errorf("dueño ajeno: sin orden: %v", err)
	}
	geteuid = old
	fijaVolumen(t, false, true, "")
	err = abrir(seguro)
	crudo(err)
	var e *i18n.Error
	if !errors.As(err, &e) || e.Code != "sys.err.outdir_mount" || strings.Contains(i18n.In(i18n.En, err), "chmod o") || !strings.Contains(i18n.In(i18n.En, err), "umask=077") {
		t.Errorf("fat: pide remontar sin orden chmod: %v", err)
	}
	os.Chmod(seguro, 0o700)
	if err := abrir(seguro); err != nil {
		t.Errorf("fat privado se acepta: %v", err)
	}
}
