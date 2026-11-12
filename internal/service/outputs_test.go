package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// La orden chmod sugerida solo se agrega si la ruta es segura de pegar en una terminal (sin espacios, $, comillas...).
func TestSugerenciaChmodSoloConRutaSegura(t *testing.T) {
	old := AncestorInfo
	AncestorInfo = func(string) (os.FileMode, uint32, error) { return 0o755, uint32(os.Getuid()), nil }
	t.Cleanup(func() { AncestorInfo = old })
	st := NewCoreSettings("fabrica", t.TempDir())
	for nombre, c := range map[string]struct {
		dir string
		con bool
	}{"normal": {"salidas", true}, "espacio": {"mis salidas", false}, "subshell": {"$(id)", false}, "comilla": {"it's", false}, "punto y coma": {"a;b", false}, "acentos": {"Música", true}, "bidi": {"a\u202eb", false}} {
		t.Run(nombre, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), c.dir)
			os.Mkdir(dir, 0o700)
			os.Chmod(dir, 0o755)
			_, err := CheckOutputs(dir, st, false)
			if err == nil || !strings.Contains(err.Error(), "prefs.outputs.permisos:") {
				t.Fatalf("esperaba permisos: %v", err)
			}
			if got := strings.Contains(err.Error(), "corrígelo con: chmod 700 "); got != c.con {
				t.Fatalf("sugerencia = %v, quería %v: %v", got, c.con, err)
			}
		})
	}
}
