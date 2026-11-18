package diag

import (
	"strings"
	"testing"
)

// La ayuda marca tos e interval como no disponibles en Windows (las dos fallan allá).
func TestAyudaDiagMarcaOpcionesSoloLinux(t *testing.T) {
	for _, k := range []string{"tos (0-255, solo Linux", "interval (0.2-60, solo Linux"} {
		if !strings.Contains(help, k) {
			t.Errorf("la ayuda no contiene %q", k)
		}
	}
}
