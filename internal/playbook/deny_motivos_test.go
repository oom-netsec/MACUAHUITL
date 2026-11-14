package playbook

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Los motivos de rechazo de sintaxis dicen qué se rechaza y qué hacer; en inglés van con comillas ASCII.
func TestMotivosDeSintaxisDicenQueHacer(t *testing.T) {
	for cmd, hint := range map[string][2]string{
		"show version ; reload":          {"un comando por línea", "one command per line"},
		"show version > flash:x":         {"ningún lugar del comando", "anywhere in the command"},
		"show version | include ->":      {"dentro de un filtro", "inside a filter"},
		"show version `x`":               {"valor literal", "literal value"},
		"show version | include \"":      {"ciérralas o quítalas", "close it or remove it"},
		"show version | include a|sed x": {"reescribe la alternancia", "rewrite the alternation"},
	} {
		plat := "ios-xe"
		if strings.HasSuffix(cmd, "include \"") {
			plat = "nx-os" // las comillas solo se validan en nx-os
		}
		err := CheckDenied(plat, cmd)
		if err == nil {
			t.Fatalf("%q: no se rechazó", cmd)
		}
		es, en := i18n.In("es", err), i18n.In("en", err)
		if !strings.Contains(es, hint[0]) || !strings.Contains(en, hint[1]) || strings.ContainsAny(en, "«»") {
			t.Errorf("%q:\n es=%s\n en=%s", cmd, es, en)
		}
	}
}
