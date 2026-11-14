package i18n

import (
	"strings"
	"testing"
)

// La etiqueta de la credencial anterior queda guardada en la bóveda como «(anterior)»: el texto en inglés cita la
// etiqueta real, y --iface NAME no deja el NOMBRE en español.
func TestTextosEnQueCitanCosasReales(t *testing.T) {
	if got := Msg(En, "mctl.credrotate.note_3", nil); !strings.Contains(got, `"<label> (anterior)"`) {
		t.Errorf("note_3 en: %q", got)
	}
	if got := Msg(En, "mctl.metrics.iface_more", A("shown", 1, "total", 2)); !strings.Contains(got, "--iface NAME") || strings.Contains(got, "NOMBRE") {
		t.Errorf("iface_more en: %q", got)
	}
}
