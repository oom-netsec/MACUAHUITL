package i18ntest

import (
	"os"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Main es el TestMain de los paquetes cuyas pruebas comparan textos en español: el idioma canónico es el inglés, pero
// esas pruebas (cientos de llamadas con un contexto sin idioma) se quedan en es por omisión. Las pruebas de regresión
// por RPC piden es explícito, y las que verifican «sin idioma sale inglés» usan Default(t, "en").
func Main(m *testing.M) {
	i18n.SetDefault(i18n.Es)
	os.Exit(m.Run())
}

// Default fija el idioma por omisión durante la prueba y lo restaura al terminar.
func Default(t *testing.T, loc string) {
	t.Helper()
	prev := i18n.SetDefault(loc)
	t.Cleanup(func() { i18n.SetDefault(prev) })
}
