package analyze

import "testing"

// La cabecera vieja (español) y la nueva (inglés) se leen igual: hay evidencia guardada con las dos.
func TestCabeceraAceptaEspanolEIngles(t *testing.T) {
	for _, h := range []string{
		"===== ronda 2 · 2026-11-05T09:00:00Z · show ntp status · comando inválido · incompleto =====",
		"===== round 2 · 2026-11-05T09:00:00Z · show ntp status · invalid command · incomplete =====",
	} {
		m := headerRe.FindStringSubmatch(h)
		if m == nil || m[3] != "show ntp status" {
			t.Fatalf("%q: %q", h, m)
		}
		if m[4] == "" || m[5] == "" {
			t.Fatalf("marcas perdidas en %q: %q", h, m)
		}
	}
}
