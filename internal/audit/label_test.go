package audit

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// 43e-9: la clave guardada se queda; solo la etiqueta se traduce, y lo desconocido sale tal cual.
func TestActionLabel(t *testing.T) {
	for action, want := range map[string][2]string{
		"hosts.crear":    {"host creado", "host created"},
		"hosts.editar":   {"host editado", "host edited"},
		"hosts.borrar":   {"host borrado", "host deleted"},
		"hosts.importar": {"hosts importados", "hosts imported"},
		"hosts.exportar": {"hosts exportados", "hosts exported"},
		"diag.run":       {"diag.run", "diag.run"},
	} {
		if got := ActionLabel(i18n.Es, action); got != want[0] {
			t.Errorf("%s es: %q", action, got)
		}
		if got := ActionLabel(i18n.En, action); got != want[1] {
			t.Errorf("%s en: %q", action, got)
		}
	}
}
