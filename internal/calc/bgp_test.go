package calc

import (
	"strings"
	"testing"
)

func u32(v uint32) *uint32 { return &v }

func best(t *testing.T, rs []Route, o BGPOptions) BGPResult {
	t.Helper()
	r, err := BGPBestPath(rs, o)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// base: dos rutas eBGP idénticas salvo lo que cada caso cambie.
func pair() []Route {
	return []Route{
		{Name: "A", ASPath: "65001 65010", Origin: "i", EBGP: true, RouterID: "10.0.0.1", Neighbor: "192.0.2.1", AgeSeconds: 100},
		{Name: "B", ASPath: "65001 65010", Origin: "i", EBGP: true, RouterID: "10.0.0.2", Neighbor: "192.0.2.2", AgeSeconds: 100},
	}
}

func TestBGPEachStep(t *testing.T) {
	cases := []struct {
		name, winner, step string
		mut                func(rs []Route)
	}{
		{"weight", "B", "weight", func(rs []Route) { rs[1].Weight = 100 }},
		{"local-pref", "B", "local-preference", func(rs []Route) { rs[0].LocalPref = u32(90) }}, // A baja de 100
		// Con el mismo weight explícito decide el paso de originada localmente.
		{"local", "B", "originada localmente", func(rs []Route) { rs[0].Weight = 32768; rs[1].Local = true }},
		// IOS da weight 32768 a lo originado localmente: le gana a una recibida con weight 100.
		{"local weight 32768", "A", "weight", func(rs []Route) { rs[0].Local = true; rs[1].Weight = 100 }},
		{"as-path", "B", "longitud de AS_PATH", func(rs []Route) {
			rs[0].ASPath = "65001 65002 65010"
			rs[1].ASPath = "65001 (65100 65101) {65010,65011}"
		}},
		{"origin", "A", "origin", func(rs []Route) { rs[1].Origin = "?" }},
		{"med", "B", "MED", func(rs []Route) { rs[0].MED = u32(50); rs[1].MED = u32(10) }},
		{"med ausente = 0", "A", "MED", func(rs []Route) { rs[1].MED = u32(1) }},
		{"ebgp", "A", "eBGP sobre iBGP", func(rs []Route) { rs[1].EBGP = false }},
		{"igp", "B", "métrica IGP al next-hop", func(rs []Route) { rs[0].IGPMetric = 20; rs[1].IGPMetric = 10 }},
		{"oldest", "B", "ruta eBGP más antigua", func(rs []Route) { rs[1].AgeSeconds = 500 }},
		{"router-id", "A", "router-ID", func(rs []Route) {}},
		{"edad no cuenta en iBGP", "A", "router-ID", func(rs []Route) { rs[0].EBGP, rs[1].EBGP, rs[1].AgeSeconds = false, false, 500 }},
		{"AS_SET suma 1", "A", "router-ID", func(rs []Route) { rs[0].ASPath = "65001 {65002,65003}" }},
		{"cluster", "B", "longitud de CLUSTER_LIST", func(rs []Route) {
			rs[0].EBGP, rs[1].EBGP = false, false
			rs[0].OriginatorID, rs[1].OriginatorID = "10.9.9.9", "10.9.9.9"
			rs[0].ClusterListLen = 2
		}},
		{"originator-id", "B", "router-ID", func(rs []Route) {
			rs[0].EBGP, rs[1].EBGP = false, false
			rs[1].OriginatorID = "10.0.0.0"
		}},
		{"neighbor", "B", "dirección del vecino", func(rs []Route) { rs[1].RouterID = "10.0.0.1"; rs[0].Neighbor = "192.0.2.10" }},
	}
	for _, c := range cases {
		rs := pair()
		c.mut(rs)
		r := best(t, rs, BGPOptions{})
		if r.Best != c.winner || r.DecidedBy != c.step {
			t.Errorf("%s: ganó %s por %q, quiero %s por %q", c.name, r.Best, r.DecidedBy, c.winner, c.step)
		}
	}
}

func TestBGPMEDNeighborASAndAlwaysCompare(t *testing.T) {
	rs := pair()
	rs[0].ASPath, rs[0].MED, rs[0].AgeSeconds = "65001 65010", u32(50), 900
	rs[1].ASPath, rs[1].MED = "65002 65010", u32(10)
	if r := best(t, rs, BGPOptions{}); r.Best != "A" || r.DecidedBy != "ruta eBGP más antigua" {
		t.Fatalf("sin always-compare-med: %s por %s", r.Best, r.DecidedBy)
	}
	if r := best(t, rs, BGPOptions{AlwaysCompareMED: true}); r.Best != "B" || r.DecidedBy != "MED" {
		t.Fatalf("con always-compare-med: %s por %s", r.Best, r.DecidedBy)
	}
}

func TestBGPDeterministicMED(t *testing.T) {
	r1 := Route{Name: "R1", ASPath: "65001", MED: u32(100), EBGP: true, RouterID: "10.0.0.1", Neighbor: "192.0.2.1"}
	r2 := Route{Name: "R2", ASPath: "65002", MED: u32(0), EBGP: true, RouterID: "10.0.0.5", Neighbor: "192.0.2.5"}
	r3 := Route{Name: "R3", ASPath: "65001", MED: u32(10), EBGP: true, RouterID: "10.0.0.9", Neighbor: "192.0.2.9"}
	// Sin deterministic-med el resultado depende del orden de llegada.
	if r := best(t, []Route{r1, r2, r3}, BGPOptions{}); r.Best != "R3" || r.DecidedBy != "MED" {
		t.Fatalf("R1,R2,R3: %s por %s", r.Best, r.DecidedBy)
	}
	if r := best(t, []Route{r3, r1, r2}, BGPOptions{}); r.Best != "R2" {
		t.Fatalf("R3,R1,R2: %s", r.Best)
	}
	for _, order := range [][]Route{{r1, r2, r3}, {r3, r1, r2}, {r2, r3, r1}} {
		r := best(t, order, BGPOptions{DeterministicMED: true})
		if r.Best != "R2" || r.DecidedBy != "router-ID" {
			t.Fatalf("deterministic: %s por %s", r.Best, r.DecidedBy)
		}
	}
}

func TestBGPUnreachableAndMultipath(t *testing.T) {
	rs := pair()
	rs[0].NextHopUnreachable = true
	r := best(t, rs, BGPOptions{})
	if r.Best != "B" || r.DecidedBy != "next-hop accesible" || len(r.Excluded) != 1 {
		t.Fatalf("%+v", r)
	}
	rs = pair()
	rs[1].ASPath = "65002 65010"
	if r := best(t, rs, BGPOptions{MaximumPaths: 2}); strings.Join(r.Multipath, ",") != "A" {
		t.Fatalf("sin relax: %v", r.Multipath)
	}
	if r := best(t, rs, BGPOptions{MaximumPaths: 2, MultipathRelax: true}); strings.Join(r.Multipath, ",") != "A,B" {
		t.Fatalf("con relax: %v", r.Multipath)
	}
	rs[1].ASPath = "65001 65010"
	rs[1].IGPMetric = 5
	if r := best(t, rs, BGPOptions{MaximumPaths: 2, MultipathRelax: true}); strings.Join(r.Multipath, ",") != "A" {
		t.Fatalf("métrica distinta no es multipath: %v", r.Multipath)
	}
}

func TestBGPReport(t *testing.T) {
	r := best(t, pair(), BGPOptions{})
	txt := r.Report().Text()
	if !strings.Contains(txt, "A vs B") || !strings.Contains(txt, "Gana A") {
		t.Fatalf("%s", txt)
	}
}

func TestBGPRejects(t *testing.T) {
	bad := [][]Route{
		{{Name: "solo"}},
		{{Name: "A", Origin: "x"}, {Name: "B"}},
		{{Name: "A", ASPath: "65001 {65002"}, {Name: "B"}},
		{{Name: "A", ASPath: "abc"}, {Name: "B"}},
		{{Name: "A", RouterID: "1.2.3"}, {Name: "B"}},
		{{Name: "A", NextHopUnreachable: true}, {Name: "B", NextHopUnreachable: true}},
	}
	for _, rs := range bad {
		if _, err := BGPBestPath(rs, BGPOptions{}); err == nil {
			t.Errorf("%+v aceptado", rs)
		}
	}
}
