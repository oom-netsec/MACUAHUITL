package core

import (
	"strings"
	"testing"
)

// Con en, el análisis sale en inglés (título, detalle, explicación, acción, avisos y eventos) y sus claves
// coinciden con el json; con es, el de siempre.
func TestAnalisisIdiomaYClaves(t *testing.T) {
	h := newHarness(t, nil)
	fx := newFlotaFx(t)
	for _, lang := range []string{"", "en"} {
		sub := map[string]flotaRec{}
		for n, r := range flotaCases(t, h, lang, fx) {
			if strings.HasPrefix(n, "analysis.") {
				sub[n] = r
			}
		}
		if n := checkKeys(t, lang, sub); n < 5 {
			t.Errorf("con %q solo %d claves de análisis", lang, n)
		}
		if lang == "en" {
			j := sub["analysis.job.0"].Json
			for _, want := range []string{"Memory allocation failure", `"detail":"1 line"`, "Check Last reload reason"} {
				if !strings.Contains(j, want) {
					t.Errorf("falta %q en el análisis en inglés", want)
				}
			}
			if !strings.Contains(sub["analysis.job.0"].Text, "why: ") || strings.Contains(sub["analysis.job.0"].Text, "por qué") {
				t.Errorf("texto en inglés: %.300s", sub["analysis.job.0"].Text)
			}
			if !strings.Contains(sub["analysis.timeline.rtr2"].Text, "window:") {
				t.Errorf("texto de la línea de tiempo: %.200s", sub["analysis.timeline.rtr2"].Text)
			}
		}
	}
}
