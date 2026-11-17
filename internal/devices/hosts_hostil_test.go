package devices

import "testing"

// L6: el nombre de host y la etiqueta de credencial no admiten bidi ni ancho cero (U+200B, U+2060, U+FEFF); U+200D, U+200C y U+00AD sí valen, separadores de línea y de párrafo
// ni controles: y la orden de arranque sigue con la regla más estricta (badStartupRune). Unicode normal (ñ, acentos, CJK) sigue valiendo. El formato va ESCAPADO.
func TestNombreYEtiquetaRechazanFormatoUnicode(t *testing.T) {
	for nombre, s := range map[string]string{
		"RLO": "r1\u202etxt", "LRI": "r\u2066x", "PDI": "r\u2069x", "ancho cero": "r\u200b1", "BOM": "\ufeffr1", "LRM": "r\u200e1",
		"ALM": "r\u061c1", "separador de línea": "r\u20281", "de párrafo": "r\u20291", "NEL (C1)": "r\u00851", "tab": "r\t1", "NUL": "r\x001", "DEL": "r\x7f1",
		"RLE": "r\u202a1", "RLM": "r\u200f1", "word joiner": "r\u20601", "función aplicada": "r\u20611", "tiempos invisibles": "r\u20621", "separador invisible": "r\u20631", "coma invisible": "r\u20641",
		"etiqueta": "r\U000E00411", "etiqueta cancelar": "r\U000E007F1", "etiqueta inicio": "r\U000E00001",
	} {
		if _, err := Clean(Host{Name: s, Address: "10.0.0.1"}); err == nil {
			t.Errorf("nombre %s (%q) debía rechazarse", nombre, s)
		}
		if _, errs := validateRows([]row{{line: 2, h: FileHost{Name: "ok", Address: "10.0.0.1", CredentialLabel: s}}}); len(errs) != 1 {
			t.Errorf("etiqueta %s (%q) debía rechazarse", nombre, s)
		}
	}
	for _, s := range []string{"router-ñandú", "Sucursal Ámsterdam", "路由器1", "sw 1 (core)", "r\u200d1", "r\u200c1", "r\u00ad1", "\U0001F468\u200d\U0001F4BB"} {
		if _, err := Clean(Host{Name: s, Address: "10.0.0.1"}); err != nil {
			t.Errorf("nombre %q: %v", s, err)
		}
		if _, errs := validateRows([]row{{line: 2, h: FileHost{Name: "ok", Address: "10.0.0.1", CredentialLabel: s}}}); len(errs) != 0 {
			t.Errorf("etiqueta %q: %v", s, errs)
		}
	}
}
