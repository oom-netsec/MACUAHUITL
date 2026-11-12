package compliance

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

var spanish = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(sin|falta|línea|líneas|las|los|del|hay|presente|plantilla|configuración|sección)\b`)

func TestInformeEnInglesYClaves(t *testing.T) {
	cfg, _ := os.ReadFile("testdata/debil.txt")
	tpl, _ := os.ReadFile("testdata/plantilla.txt")
	r, err := Check(string(cfg), string(tpl))
	if err != nil {
		t.Fatal(err)
	}
	keys := i18n.Localize(&r, i18n.Es)
	if len(keys) < 10 {
		t.Errorf("pocas claves: %d", len(keys))
	}
	i18n.Localize(&r, i18n.En)
	for _, f := range append(append([]Finding{}, r.Template...), r.Hardening...) {
		// el título de una regla de plantilla es la propia línea de la plantilla y las líneas citadas son config
		txt := f.Detail
		if f.Status != Pass && spanish.MatchString(spanishFree(txt)) {
			t.Errorf("%s: español en %q", f.Rule, f.Detail)
		}
	}
	if m := spanish.FindString(r.TextIn(i18n.En)); m != "" && !strings.Contains(r.TextIn(i18n.En), "<oculto>") {
		t.Logf("revisa: %s", m)
	}
}

// spanishFree quita las líneas de configuración citadas, que son datos.
func spanishFree(s string) string {
	return regexp.MustCompile(`line \d+: [^;]*`).ReplaceAllString(s, "")
}

func TestPlantillaErroresCodificados(t *testing.T) {
	for _, c := range []struct{ tpl, es, en string }{
		{"- foo\n bar\n", "compliance: plantilla línea 1: una línea prohibida no puede tener hijos", "compliance: template line 1: a forbidden line cannot have children"},
		{"? foo\n", "compliance: plantilla línea 1: una sección opcional necesita reglas", "compliance: template line 1: an optional section needs rules"},
		{"# nada\n", "compliance: la plantilla no tiene reglas", "compliance: the template has no rules"},
	} {
		_, err := ParseTemplate(c.tpl)
		co, ok := err.(i18n.Coded)
		if err == nil || !ok || err.Error() != c.es || co.Localize(i18n.En) != c.en {
			t.Errorf("%q: %v", c.tpl, err)
		}
	}
}
