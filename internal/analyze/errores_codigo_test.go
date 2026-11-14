package analyze

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Las reglas YAML del usuario: cada error de validación llega con código (es el de siempre, en en inglés).
func TestErroresDeReglasConCodigo(t *testing.T) {
	base := "- id: r1\n  title: T\n  explanation: E\n  action: A\n  severity: alta\n  commands: [show x]\n  check: match\n"
	cases := []struct{ name, yaml, es, en string }{
		{"obligatorios", "- id: r1\n", "reglas r.yaml: r1: id, title, explanation y action son obligatorios", "rules r.yaml: r1: id, title, explanation and action are required"},
		{"severidad", strings.Replace(base, "alta", "rara", 1), `reglas r.yaml: r1: severidad "rara" inválida (critica, alta, media, baja, info)`, `rules r.yaml: r1: invalid severity "rara" (critica, alta, media, baja, info)`},
		{"sin comandos", strings.Replace(base, "[show x]", "[]", 1), "reglas r.yaml: r1: sin comandos", "rules r.yaml: r1: no commands"},
		{"check", strings.Replace(base, "match", "raro", 1), `reglas r.yaml: r1: check "raro" desconocido`, `rules r.yaml: r1: unknown check "raro"`},
		{"param sobra", base + "  params: {pattern: x, otro: y}\n", `reglas r.yaml: r1: parámetro "otro" no aplica a match`, `rules r.yaml: r1: parameter "otro" does not apply to match`},
		{"numero", base + "  params: {pattern: x, min: abc}\n", `reglas r.yaml: r1: parámetro min: "abc" no es un número`, `rules r.yaml: r1: parameter min: "abc" is not a number`},
		{"repetido", base + "  params: {pattern: x}\n" + base + "  params: {pattern: x}\n", "reglas r.yaml: id r1 repetido", "rules r.yaml: duplicate id r1"},
	}
	for _, c := range cases {
		_, err := LoadRules(fstest.MapFS{"r.yaml": {Data: []byte(c.yaml)}})
		if err == nil || err.Error() != c.es || i18n.English(err) != c.en {
			t.Errorf("%s: %v / %q", c.name, err, i18n.English(err))
		}
	}
}
