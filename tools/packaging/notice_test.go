package packaging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Toda biblioteca de JavaScript que va dentro de la app (de producción, también las transitivas) lleva su aviso en NOTICE.
func TestNoticeTraeDependenciasDeLaUI(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(), "ui", "frontend", "package-lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Packages map[string]struct{ Dev, DevOptional, Optional bool }
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(filepath.Join(repoRoot(), "NOTICE"))
	if err != nil {
		t.Fatal(err)
	}
	// Solo la lista de bibliotecas: en los textos de licencia salen palabras como "merge" o "copy".
	notice, _, ok := strings.Cut(string(raw), "Texto de la licencia MIT")
	if !ok {
		t.Fatal("NOTICE sin el texto de la licencia MIT")
	}
	n := 0
	for path, p := range lock.Packages {
		i := strings.LastIndex(path, "node_modules/")
		if i < 0 || p.Dev || p.DevOptional || p.Optional {
			continue
		}
		n++
		name := path[i+len("node_modules/"):]
		if !regexp.MustCompile(`(?m)(^|[\s,])` + regexp.QuoteMeta(name) + `([\s,]|$)`).MatchString(notice) {
			t.Errorf("NOTICE no menciona %s", name)
		}
	}
	if n == 0 {
		t.Fatal("package-lock.json sin dependencias de producción")
	}
}
