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

// El motivo de cada error de la carpeta de salidas es el prefijo prefs.outputs.<motivo> de su texto, aunque haya
// varias claves para el mismo motivo.
func TestMotivoDeCarpetaDeSalidasIgualAlPrefijo(t *testing.T) {
	n := 0
	for _, c := range Codes() {
		if !strings.HasPrefix(c, "prefs.outputs.") || c == "prefs.outputs.issue" || c == "prefs.outputs.note" {
			continue
		}
		n++
		prefix, _, _ := strings.Cut(Msg(Es, c, nil), ":")
		if got := Reason(c); got != prefix {
			t.Errorf("%s: reason %q, prefijo %q", c, got, prefix)
		}
		if pe, _, _ := strings.Cut(Msg(En, c, nil), ":"); pe != prefix {
			t.Errorf("%s: el prefijo en inglés es %q", c, pe)
		}
	}
	if n < 12 {
		t.Fatalf("solo %d códigos", n)
	}
}
