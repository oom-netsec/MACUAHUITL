package dnsq

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Las llaves se generan en cada corrida y las fechas dependen del reloj: se enmascaran.
var volatileTime = regexp.MustCompile(`\d{4}-\d\d-\d\dT[\d:]+(Z|[+-]\d\d:\d\d)|"(KeyTags|DS)":\[[^\]]*\]`)

func viewDNSSEC(r any) string {
	return volatileTime.ReplaceAllString(viewDNS(r), "T")
}

// escenariosDNSSEC corre CheckDNSSEC en los casos que producen errores, avisos y valores con palabras.
func escenariosDNSSEC(t *testing.T) map[string]DNSSECReport {
	t.Helper()
	out := map[string]DNSSECReport{}
	run := func(name string, l *lab, roots []Root, anchors []string) {
		rep, err := CheckDNSSEC(context.Background(), l.dial, "ejemplo.lab", roots, anchors, opts())
		if err != nil {
			t.Fatal(err)
		}
		out[name] = rep
	}
	l, roots, zones := hierarchy(t, true)
	run("valida", l, roots, []string{zones["."].ds()})
	l, roots, zones = hierarchy(t, true)
	zones["ejemplo.lab."].resign(t, time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	run("vencida", l, roots, []string{zones["."].ds()})
	l, roots, zones = hierarchy(t, true)
	zones["lab."].resign(t, time.Now().Add(-time.Hour), time.Now().Add(3*24*time.Hour))
	run("vence-pronto", l, roots, []string{zones["."].ds()})
	l, roots, _ = hierarchy(t, true)
	run("ancla-ajena", l, roots, []string{hierarchyKey(t)})
	l, roots, _ = hierarchy(t, false)
	run("sin-firmar", l, roots, nil)
	l, roots, zones = hierarchy(t, true)
	zones["ejemplo.lab."].resign(t, time.Now().Add(time.Hour), time.Now().Add(48*time.Hour))
	run("aun-no-valida", l, roots, []string{zones["."].ds()})
	return out
}

// Regresión: el JSON en español de CheckDNSSEC es el de antes del catálogo (UPDATE_GOLDEN=1 lo reescribe).
func TestDNSSECEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for n, r := range escenariosDNSSEC(t) {
		got[n] = viewDNSSEC(r)
	}
	const file = "testdata/dnssec_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for n, g := range got {
		if g != want[n] {
			t.Errorf("%s cambió:\n got: %s\nwant: %s", n, g, want[n])
		}
	}
}

// Con en, los errores, avisos y valores con palabras del informe salen en inglés; los datos no cambian.
func TestDNSSECEnIngles(t *testing.T) {
	spanish := regexp.MustCompile(`(?i)\b(firma|vence|vencida|raíz|zona|llave|padre|ninguna|desconocido|aún|publica|sin)\b`)
	want := map[string]string{
		"vencida":       "DNSKEY signature: signature expired on",
		"sin-firmar":    "the root of this trace does not publish a DNSKEY",
		"ancla-ajena":   "no key of the zone matches the DS (or the trust anchor)",
		"aun-no-valida": "DNSKEY signature: signature not yet valid",
	}
	for n, r := range escenariosDNSSEC(t) {
		en := Localize(r, "en").(DNSSECReport)
		for _, l := range en.Chain {
			if spanish.MatchString(l.Error) {
				t.Errorf("%s: %q sin traducir", n, l.Error)
			}
		}
		for _, w := range en.Warnings {
			if spanish.MatchString(w) {
				t.Errorf("%s: %q sin traducir", n, w)
			}
		}
		if spanish.MatchString(en.Denial) {
			t.Errorf("%s: denial %q", n, en.Denial)
		}
		if w, ok := want[n]; ok && !strings.Contains(en.Chain[len(en.Chain)-1].Error, w[strings.Index(w, ":")+2:]) {
			t.Errorf("%s: %q no contiene %q", n, en.Chain[len(en.Chain)-1].Error, w)
		}
	}
	// Localize(es) es identidad (el servicio la usa siempre).
	for n, r := range escenariosDNSSEC(t) {
		if a, b := viewDNSSEC(r), viewDNSSEC(Localize(r, "es")); a != b {
			t.Errorf("%s: Localize(es) cambia el JSON", n)
		}
	}
}

// Los errores de ParseServer y ParseType llevan código y salen en inglés con en.
func TestParseErroresEn(t *testing.T) {
	_, err := ParseServer("tcp://x y")
	_, err2 := ParseType("ZZZ")
	for _, e := range []error{err, err2} {
		if e == nil || i18n.In("en", e) == e.Error() || i18n.In("en", e) == "" {
			t.Errorf("sin traducir: %v", e)
		}
	}
	if err2.Error() != `dnsq: tipo de registro desconocido "ZZZ"` {
		t.Errorf("es cambió: %q", err2.Error())
	}
	if got := i18n.In("en", err2); got != `dnsq: unknown record type "ZZZ"` {
		t.Errorf("en: %q", got)
	}
}
