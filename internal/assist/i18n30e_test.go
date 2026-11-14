package assist

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

var esVisible = regexp.MustCompile(`[áéíóúñ¿¡«»]|\b(hazlo|hazla|a mano|reversa|equipo|solo|línea|lista cerrada|puerto|sobran|falta|debe|nombra)\b`)

// Cada motivo de la restauración por diff sale en inglés sin restos de español y en es es el de siempre (lo fija el golden).
func TestRestoreWhyEnEnglish(t *testing.T) {
	seen := 0
	for _, cases := range [][]struct{ name, backup, want string }{refusalCases(), closedCases()} {
		for _, tc := range cases {
			p, _ := reviewPlan(t, tc.backup, func(c *RestoreChange) { c.Partial = true })
			for _, r := range p.Refused {
				seen++
				if r.WhyT.In(i18n.Es) != r.Why {
					t.Errorf("%s: es %q != %q", tc.name, r.WhyT.In(i18n.Es), r.Why)
				}
				if en := r.WhyT.In(i18n.En); en == "" || esVisible.MatchString(en) {
					t.Errorf("%s: en %q", tc.name, en)
				}
			}
		}
	}
	if seen < 40 {
		t.Fatalf("pocos motivos probados: %d", seen)
	}
}

// El error de armado del plan (ErrInvalidPlan) y el de la lista cerrada salen en inglés; es es el de siempre y se sigue reconociendo.
func TestInvalidPlanEsYEn(t *testing.T) {
	_, err := reviewPlan(t, rep(reviewRunning, "hostname SW1\n", "hostname SW1\nreload\n"), nil)
	if !errors.Is(err, ErrRestoreRefused) {
		t.Fatal(err)
	}
	dp := DevicePlan{Device: "SW1", Pre: []string{"show vlan brief"}, Apply: []string{"vlan 10"}, Rollback: []string{"no vlan 10", "hostname X"}, Post: []string{"show vlan brief"},
		Expect: []Expect{{Command: "show vlan brief", Line: "10", Present: true}}}
	err = Validate(Plan{Function: SnippetVlan.Name, Devices: []DevicePlan{dp}}, SnippetVlan)
	var c i18n.Coded
	if !errors.Is(err, ErrInvalidPlan) || !errors.As(err, &c) || c.Reason() != "assist.invalid_plan" {
		t.Fatalf("%#v", err)
	}
	if es := err.Error(); !strings.HasPrefix(es, "assist: plan inválido: SW1: Rollback ") || !strings.Contains(es, "fuera de la lista cerrada") {
		t.Fatalf("es: %q", es)
	}
	en := c.Localize(i18n.En)
	if !strings.HasPrefix(en, "assist: invalid plan: SW1: Rollback ") || !strings.Contains(en, "outside the closed list") || esVisible.MatchString(en) {
		t.Fatalf("en: %q", en)
	}
}

// Los Check de cada función rechazan en los dos idiomas: la pieza de Check va anidada en el error del plan.
func TestCheckErrorsEnEnglish(t *testing.T) {
	cases := []struct {
		fn    Function
		dp    DevicePlan
		wantE string
	}{
		{SnippetVlan, DevicePlan{Device: "SW1", Apply: []string{"vlan 10", "name A"}, Rollback: []string{"no vlan 11"}}, "the rollback must delete only VLAN"},
		{SnippetStaticRoute, DevicePlan{Device: "SW1", Apply: []string{"ip route 10.0.0.1 255.0.0.0 10.0.0.2"}, Rollback: []string{"no ip route 10.0.0.1 255.0.0.0 10.0.0.2"}}, "host bits"},
	}
	for _, tc := range cases {
		dp := tc.dp
		dp.Pre, dp.Post = []string{"show running-config"}, []string{"show running-config"}
		dp.Expect = []Expect{{Command: "show running-config", Line: "x", Present: true}}
		err := Validate(Plan{Function: tc.fn.Name, Devices: []DevicePlan{dp}}, tc.fn)
		var c i18n.Coded
		if !errors.As(err, &c) {
			t.Fatalf("%s: %v", tc.fn.Name, err)
		}
		if en := c.Localize(i18n.En); !strings.Contains(en, tc.wantE) || esVisible.MatchString(strings.ReplaceAll(en, "Rollback", "")) {
			t.Errorf("%s en: %q", tc.fn.Name, en)
		}
	}
}

// Red de seguridad: en todo lerr("es", "en") del código el inglés no trae español y no es el mismo texto.
func TestLerrLiteralsAreEnglish(t *testing.T) {
	rx := regexp.MustCompile(`lerr\(\s*"((?:[^"\\]|\\.)*)",\s*"((?:[^"\\]|\\.)*)"`)
	files, _ := filepath.Glob("*.go")
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, m := range rx.FindAllStringSubmatch(string(b), -1) {
			n++
			es, en := m[1], m[2]
			if esVisible.MatchString(strings.ReplaceAll(en, "Rollback", "")) {
				t.Errorf("%s: en con español: %q", f, en)
			}
			if es == en && !strings.HasPrefix(es, "%q: ") && !strings.Contains(es, "Pre/Post") && !strings.HasPrefix(es, "Apply") && !strings.HasPrefix(es, "Rollback") {
				t.Errorf("%s: sin traducir: %q", f, es)
			}
		}
	}
	if n < 100 {
		t.Fatalf("pocos lerr revisados: %d", n)
	}
}
