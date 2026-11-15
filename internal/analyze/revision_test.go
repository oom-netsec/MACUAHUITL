package analyze

import (
	"testing"
	"time"
)

// Un vecino MP-BGP con 5 prefijos IPv4 y 0 IPv6 no debe parecer que perdió prefijos si la ronda 2
// trae el comando IPv6 porque el IPv4 salió incompleto: son familias distintas.
func TestBGPNoMezclaFamiliasEntreRondas(t *testing.T) {
	sec := func(r int, cmd, tx string, inc bool) Section {
		return Section{Device: "X_10.9.9.9", Round: r, At: time.Date(2026, 11, 4, 10, r, 0, 0, time.UTC), Command: cmd, Text: tx, Incomplete: inc}
	}
	b := &Bundle{Sections: []Section{
		sec(1, "show ip bgp summary", bgpSummary("1w2d", "5"), false),
		sec(1, "show bgp ipv6 unicast summary", bgpSummary("1w2d", "0"), false),
		sec(2, "show ip bgp summary", bgpSummary("1w2d", "5"), true),
		sec(2, "show bgp ipv6 unicast summary", bgpSummary("1w2d", "0"), false),
	}}
	if r := Analyze(b, rules(t), Options{}); hasRule(r, "bgp-prefijos-a-cero") {
		t.Errorf("falso positivo por mezcla de familias: %v", keys(r.Findings))
	}
}
