package cleaner

import (
	"os"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestInformeYSalidaEnIngles(t *testing.T) {
	b, _ := os.ReadFile("testdata/sucia.txt")
	r := Clean(string(b), Options{Sort: true})
	es := r.Text()
	if r.OutputIn(i18n.Es) != r.Output || !strings.Contains(r.Output, "! HUERFANA: ") {
		t.Fatal("la salida en español cambió")
	}
	keys := i18n.Localize(&r, i18n.En)
	if len(keys) < len(r.Orphans) {
		t.Errorf("%d claves para %d huérfanas", len(keys), len(r.Orphans))
	}
	en, out := r.TextIn(i18n.En), r.OutputIn(i18n.En)
	for _, bad := range []string{"HUÉRFANAS", "línea", "no existe", "quitadas", "Las huérfanas"} {
		if strings.Contains(en, bad) {
			t.Errorf("español %q en:\n%s", bad, en)
		}
	}
	if strings.Contains(out, "HUERFANA") || !strings.Contains(out, "! ORPHAN: route-map RM-FALTA does not exist") || es == en {
		t.Errorf("salida en inglés:\n%s", out)
	}
}

func TestMotivoClassMapSinUso(t *testing.T) {
	w := i18n.Tx("cleaner.why.unused", "name", "CM")
	if w.In(i18n.Es) != "class-map CM sin uso (ningún policy-map la usa)" || w.In(i18n.En) != "class-map CM is unused (no policy-map uses it)" {
		t.Error(w.In(i18n.Es), w.In(i18n.En))
	}
}
