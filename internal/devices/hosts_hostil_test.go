package devices

import "testing"

// L6: el nombre de host y la etiqueta de credencial no admiten formato Unicode (bidi, ancho cero), separadores de línea y de párrafo
// ni controles: la regla de badStartupRune. Unicode normal (ñ, acentos, CJK) sigue valiendo. El formato va ESCAPADO.
func TestNombreYEtiquetaRechazanFormatoUnicode(t *testing.T) {
	for nombre, s := range map[string]string{
		"RLO": "r1\u202etxt", "LRI": "r\u2066x", "PDI": "r\u2069x", "ancho cero": "r\u200b1", "ZWJ": "r\u200d1", "BOM": "\ufeffr1", "LRM": "r\u200e1",
		"ALM": "r\u061c1", "separador de línea": "r\u20281", "de párrafo": "r\u20291", "NEL (C1)": "r\u00851", "tab": "r\t1", "NUL": "r\x001", "DEL": "r\x7f1",
		"tag": "r\U000e00411", "soft hyphen": "r\u00ad1",
	} {
		if _, err := Clean(Host{Name: s, Address: "10.0.0.1"}); err == nil {
			t.Errorf("nombre %s (%q) debía rechazarse", nombre, s)
		}
		if _, errs := validateRows([]row{{line: 2, h: FileHost{Name: "ok", Address: "10.0.0.1", CredentialLabel: s}}}); len(errs) != 1 {
			t.Errorf("etiqueta %s (%q) debía rechazarse", nombre, s)
		}
	}
	for _, s := range []string{"router-ñandú", "Sucursal Ámsterdam", "路由器1", "sw 1 (core)"} {
		if _, err := Clean(Host{Name: s, Address: "10.0.0.1"}); err != nil {
			t.Errorf("nombre %q: %v", s, err)
		}
		if _, errs := validateRows([]row{{line: 2, h: FileHost{Name: "ok", Address: "10.0.0.1", CredentialLabel: s}}}); len(errs) != 0 {
			t.Errorf("etiqueta %q: %v", s, errs)
		}
	}
}
