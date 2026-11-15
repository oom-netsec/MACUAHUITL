package topo

import (
	"strings"
	"testing"
)

// cdpMulti arma un "show cdp neighbors detail" con un vecino por tupla {nombre, ifaz local, ifaz remota, vlan nativa}.
func cdpMulti(vs ...[4]string) string {
	var sb strings.Builder
	for _, v := range vs {
		sb.WriteString("-------------------------\nDevice ID: " + v[0] + "\nPlatform: cisco WS-C3560,  Capabilities: Switch IGMP \nInterface: " + v[1] + ",  Port ID (outgoing port): " + v[2] + "\nHoldtime : 150 sec\n\n")
		if v[3] != "" {
			sb.WriteString("Native VLAN: " + v[3] + "\nDuplex: " + map[bool]string{true: "full", false: "half"}[v[3] != "20"] + "\n\n")
		}
	}
	return sb.String()
}

func sinSegmento(t *testing.T, g Graph) {
	t.Helper()
	for _, n := range g.Nodes {
		if n.Kind == KindSegment {
			t.Fatalf("segmento falso:\n%s", g.Text())
		}
	}
}

func TestAPsConLaMismaInterfazNoFormanSegmento(t *testing.T) {
	g := Build([]Device{{Name: "SW9", Outputs: map[string]string{"show cdp neighbors detail": cdpMulti(
		[4]string{"AP1", "GigabitEthernet1/0/1", "GigabitEthernet0"},
		[4]string{"AP2", "GigabitEthernet1/0/2", "GigabitEthernet0"},
		[4]string{"AP3", "GigabitEthernet1/0/3", "GigabitEthernet0"})}}}, nil, "")
	sinSegmento(t, g)
	if len(g.Links) != 3 {
		t.Fatalf("enlaces = %d, quería 3", len(g.Links))
	}
}

func TestTelefonosConPort1NoFormanSegmento(t *testing.T) {
	g := Build([]Device{{Name: "SW9", Outputs: map[string]string{"show cdp neighbors detail": cdpMulti(
		[4]string{"aa-tel1", "GigabitEthernet1/0/1", "Port 1"},
		[4]string{"aa-tel2", "GigabitEthernet1/0/2", "Port 1"},
		[4]string{"aa-tel3", "GigabitEthernet1/0/3", "Port 1"})}}}, nil, "")
	sinSegmento(t, g)
}

func TestSegmentoRealConNombresEInterfacesAsimetricos(t *testing.T) {
	// zz ve a tres equipos "aa…" por la misma interfaz; cada uno anuncia una interfaz distinta.
	g := Build([]Device{{Name: "zz", Outputs: map[string]string{"show cdp neighbors detail": cdpMulti(
		[4]string{"aa1", "GigabitEthernet0/1", "GigabitEthernet0/7"},
		[4]string{"aa2", "GigabitEthernet0/1", "GigabitEthernet0/8"},
		[4]string{"aa3", "GigabitEthernet0/1", "GigabitEthernet0/9"})}}}, nil, "")
	n := 0
	for _, x := range g.Nodes {
		if x.Kind == KindSegment {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("segmentos = %d, quería 1:\n%s", n, g.Text())
	}
}

func hay(g Graph, kind string) bool {
	for _, f := range g.Findings {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

func TestSegmentoConservaVLANNativaYDuplex(t *testing.T) {
	// A ve a B, C y D por Gi0/1 (segmento); A anuncia VLAN 10 en su lado hacia B y B anuncia 20 hacia A.
	a := cdpMulti([4]string{"B", "GigabitEthernet0/1", "GigabitEthernet0/1", "10"}, [4]string{"C", "GigabitEthernet0/1", "GigabitEthernet0/1", "10"}, [4]string{"D", "GigabitEthernet0/1", "GigabitEthernet0/1", "10"})
	b := cdpMulti([4]string{"A", "GigabitEthernet0/1", "GigabitEthernet0/1", "20"})
	g := Build([]Device{{Name: "A", Outputs: map[string]string{"show cdp neighbors detail": a}}, {Name: "B", Outputs: map[string]string{"show cdp neighbors detail": b}}}, nil, "")
	seg := false
	for _, n := range g.Nodes {
		seg = seg || n.Kind == KindSegment
	}
	if !seg {
		t.Fatalf("faltó el segmento:\n%s", g.Text())
	}
	if !hay(g, "native_vlan") {
		t.Errorf("se perdió native_vlan: %+v", g.Findings)
	}
	if !hay(g, "duplex") {
		t.Errorf("se perdió duplex: %+v", g.Findings)
	}
	if hay(g, "one_sided") {
		t.Errorf("one_sided falso con el segmento: %+v", g.Findings)
	}
}

func TestSVGDelSegmentoEnIngles(t *testing.T) {
	g := Build([]Device{{Name: "zz", Outputs: map[string]string{"show cdp neighbors detail": cdpMulti(
		[4]string{"aa1", "GigabitEthernet0/1", "GigabitEthernet0/7"},
		[4]string{"aa2", "GigabitEthernet0/1", "GigabitEthernet0/8"},
		[4]string{"aa3", "GigabitEthernet0/1", "GigabitEthernet0/9"})}}}, nil, "")
	if en := g.SVGIn("en"); strings.Contains(en, "segmento") || !strings.Contains(en, "shared segment (4 devices)") {
		t.Errorf("SVG en inglés: %s", en)
	}
	if es := g.SVG(); !strings.Contains(es, "segmento compartido (4 equipos)") || es != g.SVGIn("es") {
		t.Errorf("SVG en español: %s", es)
	}
}
