package topo

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"
)

func TestLoadPatrolDir(t *testing.T) {
	devs, err := LoadPatrolDir("testdata/trabajo_20261104-100000")
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 2 || devs[0].Name != "SW1" || devs[0].IP != "10.0.0.1" || devs[0].Platform != "C9300-48P" || devs[0].Version != "17.09.04a" {
		t.Fatalf("equipos = %+v", devs)
	}
}

func kinds(g Graph) map[string]int {
	m := map[string]int{}
	for _, f := range g.Findings {
		m[f.Kind]++
	}
	return m
}

func TestBuildDesdeTrabajo(t *testing.T) {
	devs, _ := LoadPatrolDir("testdata/trabajo_20261104-100000")
	g := Build(devs, nil, "")
	if len(g.Nodes) != 4 || len(g.Links) != 4 {
		t.Fatalf("nodos=%d enlaces=%d\n%s", len(g.Nodes), len(g.Links), g.Text())
	}
	sw1 := g.node("sw1")
	if sw1 == nil || !sw1.Collected || len(sw1.RootVLANs) != 1 || sw1.RootVLANs[0] != 1 || sw1.MgmtIP != "10.0.0.1" {
		t.Fatalf("SW1 = %+v", sw1)
	}
	if n := g.node("n9k-2"); n == nil || n.Platform != "N9K-C93180YC-EX" || n.Collected {
		t.Fatalf("N9K-2 = %+v", n)
	}
	k := kinds(g)
	if k["native_vlan"] != 1 || k["duplex"] != 1 || k["one_sided"] != 1 || k["port_channel"] != 1 || len(g.Findings) != 4 {
		t.Fatalf("hallazgos = %+v", g.Findings)
	}
	for _, f := range g.Findings {
		if f.Kind == "one_sided" && !strings.Contains(f.Text, "Gi1/0/2") {
			t.Fatalf("enlace de un lado equivocado: %+v", f)
		}
	}
	for _, n := range g.Nodes {
		if n.X < 0 || n.Y < 0 || n.X > Width || n.Y > Height {
			t.Fatalf("nodo fuera del lienzo: %+v", n)
		}
	}
}

func TestBuildDesdePcap(t *testing.T) {
	g := Build(nil, []pcapan.Neighbor{{Protocol: "lldp", DeviceID: "SW9", Port: "Gi1/0/9", Platform: "C9200", MgmtIP: "10.9.9.9", NativeVLAN: 20}}, "uplink.pcap")
	if len(g.Nodes) != 2 || len(g.Links) != 1 || g.Links[0].BIf != "Gi1/0/9" || g.Links[0].Sources[0] != "pcap" {
		t.Fatalf("grafo = %s", g.Text())
	}
}

func TestSVGYJSON(t *testing.T) {
	g := Build(nil, []pcapan.Neighbor{{Protocol: "cdp", DeviceID: `<script>alert("x")</script>&`, Port: "Gi0/1"}}, "c.pcap")
	svg := g.SVG()
	if strings.Contains(svg, "<script>") {
		t.Fatal("nombre sin escapar en el SVG")
	}
	if err := xml.Unmarshal([]byte(svg), new(struct{})); err != nil {
		t.Fatalf("SVG inválido: %v", err)
	}
	var back Graph
	b, _ := json.Marshal(g)
	if err := json.Unmarshal(b, &back); err != nil || len(back.Nodes) != 2 {
		t.Fatalf("json: %v", err)
	}
}
