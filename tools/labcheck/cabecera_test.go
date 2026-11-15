package main

import "testing"

// La cabecera vieja (español) y la nueva (inglés) se leen igual: hay evidencia guardada con las dos.
func TestCabeceraAceptaEspanolEIngles(t *testing.T) {
	for _, h := range []string{
		"===== ronda 2 · 2026-11-05T09:00:00Z · show ntp status · comando inválido · incompleto =====",
		"===== round 2 · 2026-11-05T09:00:00Z · show ntp status · invalid command · incomplete =====",
	} {
		if m := headerRe.FindStringSubmatch(h); m == nil || m[1] != "show ntp status" {
			t.Fatalf("%q: %q", h, m)
		}
	}
}
