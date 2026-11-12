package core

import (
	"strings"
	"testing"
)

// Con en, los textos de la flota salen en inglés y sus claves coinciden con el json; con es, con el español de siempre.
func TestFlotaIdiomaYClaves(t *testing.T) {
	h := newHarness(t, nil)
	fx := newFlotaFx(t)
	for _, lang := range []string{"", "en"} {
		cases := flotaCases(t, h, lang, fx)
		sub := map[string]flotaRec{}
		for n, r := range cases {
			if strings.HasPrefix(n, "fleet.") {
				sub[n] = r
			}
		}
		if n := checkKeys(t, lang, sub); n < 20 {
			t.Errorf("con %q solo %d claves de la flota", lang, n)
		}
	}
	en := flotaCases(t, h, "en", fx)
	if k := en["fleet.summary"].Keys; len(k) == 0 || !strings.Contains(en["fleet.summary"].Json, "reload in the 24 h") {
		t.Errorf("summary en: %v %s", k, en["fleet.summary"].Json)
	}
	if !strings.Contains(en["fleet.path.10.1.10.20>172.31.0.1"].Json, "no evidence of the next device") {
		t.Errorf("motivo en inglés: %s", en["fleet.path.10.1.10.20>172.31.0.1"].Json)
	}
}
