package ipc

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Los errores del canal salen del catálogo: inglés por omisión, español pedido, y errors.Is sigue funcionando envueltos.
func TestErroresDelCanalEnElCatalogo(t *testing.T) {
	canal := "socket"
	if runtime.GOOS == "windows" {
		canal = "pipe" // la variante .windows nombra el pipe
	}
	for _, c := range []struct {
		err    error
		en, es string
	}{
		{ErrAlreadyRunning, "a core is already listening on the " + canal, "ya hay un núcleo escuchando en el " + canal},
		{ErrNotRunning, "the core is not running", "el núcleo no está corriendo"},
	} {
		wrapped := fmt.Errorf("%w (detalle)", c.err)
		if !errors.Is(wrapped, c.err) {
			t.Errorf("errors.Is falla con %v envuelto", c.err)
		}
		if got := i18n.In(i18n.En, wrapped); !strings.Contains(got, c.en) {
			t.Errorf("en: %q no contiene %q", got, c.en)
		}
		if got := i18n.In(i18n.Es, wrapped); !strings.Contains(got, c.es) {
			t.Errorf("es: %q no contiene %q", got, c.es)
		}
	}
}
