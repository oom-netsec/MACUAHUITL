package scripts

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestErroresDeLaPlantillaConCodigo(t *testing.T) {
	for _, c := range []struct {
		kind, es, en string
	}{
		{KindColecciones, "no hay scripts en la biblioteca para el ejemplo", "there are no scripts in the library for the example"},
		{"x", `tipo "x" desconocido: scripts o colecciones`, `unknown type "x": scripts or collections`},
	} {
		_, _, err := datos(c.kind, nil, ahora)
		if err == nil || err.Error() != c.es || i18n.English(err) != c.en {
			t.Errorf("%s: %v / %q", c.kind, err, i18n.English(err))
		}
	}
}
