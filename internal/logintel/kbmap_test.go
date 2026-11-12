package logintel

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// La ficha de la base va una vez por mnemónico en un mapa aparte, no repetida en cada patrón ni
// en cada interfaz: con miles de elementos duplicada superaría el tope del mensaje.
func TestFichasUnaVezPorMnemonico(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := range 6 {
		at := t0.Add(time.Duration(i) * time.Second)
		for j := range 3 { // 3 interfaces: mismas fichas
			b.WriteString(link("sw", fmt.Sprintf("Gi0/%d", j+1), []string{"down", "up"}[i%2], at))
		}
	}
	es, _ := ParseLines(b.String(), ParseOptions{Now: now})
	frep := Flaps(es, FlapOptions{})
	prep := Group(es, GroupOptions{})
	if len(frep.Flaps) != 3 || len(prep.Patterns) != 2 {
		t.Fatalf("flaps %d patrones %d", len(frep.Flaps), len(prep.Patterns))
	}
	for name, v := range map[string]any{"flaps": frep, "patrones": prep} {
		js, _ := json.Marshal(v)
		if n := strings.Count(string(js), `"meaning"`); n != 1 {
			t.Errorf("%s: la ficha aparece %d veces en el JSON, quiero 1", name, n)
		}
	}
	if _, ok := prep.KB["%LINK-3-UPDOWN"]; !ok {
		t.Errorf("patrones: falta la ficha en el mapa: %+v", prep.KB)
	}
	if _, ok := frep.KB["%LINK-3-UPDOWN"]; !ok || frep.Flaps[0].Mnemonic != "%LINK-3-UPDOWN" {
		t.Errorf("flaps: falta la ficha en el mapa o el mnemónico: %+v", frep.KB)
	}
}
