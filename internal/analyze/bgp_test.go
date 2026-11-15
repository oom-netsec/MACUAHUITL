package analyze

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// Formato de la documentación de Cisco (show ip bgp summary); sin validar en laboratorio.
func bgpSummary(updown, pfx string) string {
	return "BGP router identifier 10.255.0.2, local AS number 65001\n\n" +
		"Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n" +
		fmt.Sprintf("10.0.12.1       4        65000    1234    1200      145    0    0 %-9s %s\n", updown, pfx)
}

func bgpRounds(texts ...string) *Bundle {
	b := &Bundle{}
	for i, tx := range texts {
		b.Sections = append(b.Sections, Section{Device: "X_10.9.9.9", Round: i + 1, At: time.Date(2026, 11, 4, 10, i, 0, 0, time.UTC), Command: "show ip bgp summary", Text: tx})
	}
	return b
}

func hasRule(r Report, id string) bool {
	for _, k := range keys(r.Findings) {
		if strings.HasPrefix(k, id+" ") {
			return true
		}
	}
	return false
}

func TestBGPPrefijosACero(t *testing.T) {
	rs := rules(t)
	for name, c := range map[string]struct {
		a, z string
		want bool
	}{
		"de 5 a 0":                {"5", "0", true},
		"de 5 a 3":                {"5", "3", false},
		"de 0 a 0":                {"0", "0", false},
		"de Established a Idle":   {"5", "Idle", false},
		"de Established a Active": {"5", "Active", false},
	} {
		r := Analyze(bgpRounds(bgpSummary("1w2d", c.a), bgpSummary("1w2d", c.z)), rs, Options{})
		if got := hasRule(r, "bgp-prefijos-a-cero"); got != c.want {
			t.Errorf("%s: disparó=%v, quería %v (%v)", name, got, c.want, keys(r.Findings))
		}
	}
	// Una ronda intermedia sin tabla rompe la inmediatez: no se compara contra la ronda 1.
	b := bgpRounds(bgpSummary("1w2d", "5"), "", bgpSummary("1w2d", "0"))
	b.Sections = append(b.Sections[:1], b.Sections[2:]...)
	if r := Analyze(b, rs, Options{}); hasRule(r, "bgp-prefijos-a-cero") {
		t.Errorf("rondas no consecutivas: %v", keys(r.Findings))
	}
	r := Analyze(bgpRounds(bgpSummary("1w2d", "5"), bgpSummary("1w2d", "0")), rs, Options{})
	f := finding(t, r.Findings, "bgp-prefijos-a-cero X r2")
	if f.Severity != "alta" || !strings.Contains(f.Detail, "10.0.12.1") || !strings.Contains(f.Action, "received-routes") {
		t.Errorf("hallazgo: %+v", f)
	}
}
