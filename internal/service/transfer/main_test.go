package transfer

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

// Estas pruebas comparan textos en español: el idioma por omisión de la app es el inglés, aquí se fija es.
func TestMain(m *testing.M) { i18ntest.Main(m) }
