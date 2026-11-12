package compliance

import (
	"encoding/json"
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
	// la marca de secreto oculto también sale en inglés
	en := r.TextIn(i18n.En)
	if strings.Contains(en, "<oculto>") || !strings.Contains(en, "<hidden>") {
		t.Errorf("la marca de oculto en el texto en inglés:\n%s", en)
	}
	if es := (func() string { r2, _ := Check(string(cfg), string(tpl)); return r2.Text() })(); !strings.Contains(es, "<oculto>") || strings.Contains(es, "<hidden>") {
		t.Errorf("la marca de oculto en el texto en español:\n%s", es)
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

// Ningún secreto sale en el informe, en ningún idioma: contraseñas, comunidades SNMP, key-string y llaves de NTP.
func TestNingunSecretoEnElInforme(t *testing.T) {
	cfg := "hostname R1\nenable password 7 SECRETO1\nsnmp-server community COMUNIDAD2 RO\nkey chain K\n key 1\n  key-string 7 SECRETO3\nntp authentication-key 1 md5 SECRETO4 7\nntp server 10.0.0.1\n"
	tpl := "- enable password .*\n- snmp-server community .*\n- ntp authentication-key .*\nkey chain K\n key 1\n  - key-string .*\n- ntp server .*\n"
	r, err := Check(cfg, tpl)
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, loc := range []string{i18n.Es, i18n.En} {
		rr := r
		i18n.Localize(&rr, loc)
		raw, _ := json.Marshal(rr)
		all := string(raw) + rr.TextIn(loc)
		for _, sec := range []string{"SECRETO1", "COMUNIDAD2", "SECRETO3", "SECRETO4"} {
			if strings.Contains(all, sec) {
				t.Errorf("%s: el secreto %s sale en el informe:\n%s", loc, sec, all)
			}
		}
		found += strings.Count(all, "snmp-server community <")
	}
	if found == 0 {
		t.Error("la línea de la comunidad no se citó con su valor oculto")
	}
}

// Los escenarios de la regresión recorren todos los títulos y detalles de las reglas y de la plantilla.
func TestEscenariosCubrenTodosLosDetalles(t *testing.T) {
	_, ptrs := regCases(t)
	used := map[string]bool{}
	for _, v := range ptrs {
		for k := range i18n.UsedKeys(v) {
			used[k] = true
		}
	}
	for _, k := range i18n.Codes() {
		for _, prefix := range []string{"compliance.detail.", "compliance.title.", "compliance.scope."} {
			if strings.HasPrefix(k, prefix) && !used[k] {
				t.Errorf("ningún escenario de la regresión produce %s", k)
			}
		}
	}
}
