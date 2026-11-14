package i18n

import (
	"encoding/json"
	"os"
	"regexp"
	"testing"
)

// El inglés de las plantillas de snippets (mctl) es el mismo de la app: si se corrige en en.ts, aquí también.
func TestSnippetsInglesIgualQueLaApp(t *testing.T) {
	b, err := os.ReadFile("../../ui/frontend/src/lib/i18n/en.ts")
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`(?m)^  "(snippet\.[^"]+)": (".*"),$`)
	n := 0
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		var app string
		if err := json.Unmarshal([]byte(m[2]), &app); err != nil {
			t.Fatalf("%s: %v", m[1], err)
		}
		e, ok := catalog[m[1]]
		if !ok {
			continue // la app puede tener textos de snippets que mctl no usa
		}
		n++
		if e.En != app {
			t.Errorf("%s: catálogo %q, app %q", m[1], e.En, app)
		}
	}
	if n < 100 {
		t.Fatalf("solo %d claves snippet.* comparadas: ¿cambió el formato de en.ts?", n)
	}
}
