package topo

import (
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
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

func TestLoadPatrolDirSaltaSeccionesIncompletas(t *testing.T) {
	d := t.TempDir()
	dd := filepath.Join(d, "SW1_10.0.0.1")
	os.MkdirAll(dd, 0o755)
	os.WriteFile(filepath.Join(dd, "r001.txt"), []byte("===== 2026-11-04T10:00:00Z · show version =====\ncompleta\n"), 0o600)
	os.WriteFile(filepath.Join(dd, "r002.txt"), []byte("===== 2026-11-04T10:10:00Z · show version · incompleto =====\ncorta\n"), 0o600)
	devs, err := LoadPatrolDir(d)
	if err != nil || len(devs) != 1 || strings.TrimSpace(devs[0].Outputs["show version"]) != "completa" {
		t.Fatalf("%v %+v", err, devs)
	}
}

// Un equipo ve el enlace por LLDP como Et0/2 y el otro por CDP como Ethernet0/2: es un solo enlace.
func TestEnlaceUnicoEtVsEthernet(t *testing.T) {
	lldp := "------------------------------------------------\nLocal Intf: Et0/2\nChassis id: aabb.cc00.0200\nPort id: Et0/2\nSystem Name: R2\n\nTotal entries displayed: 1\n"
	cdp := "-------------------------\nDevice ID: R1\nEntry address(es): \n  IP address: 10.0.0.1\nPlatform: cisco IOSv,  Capabilities: Router \nInterface: Ethernet0/2,  Port ID (outgoing port): Ethernet0/2\nHoldtime : 150 sec\n\nTotal cdp entries displayed : 1\n"
	g := Build([]Device{
		{Name: "R1", IP: "10.0.0.1", Outputs: map[string]string{"show lldp neighbors detail": lldp}},
		{Name: "R2", IP: "10.0.0.2", Outputs: map[string]string{"show cdp neighbors detail": cdp}},
	}, nil, "")
	if len(g.Links) != 1 || len(g.Links[0].Sources) != 2 || len(g.Links[0].SeenBy) != 2 || g.Links[0].AIf != "Eth0/2" || g.Links[0].BIf != "Eth0/2" {
		t.Fatalf("enlaces = %+v", g.Links)
	}
}

func TestTextInIdioma(t *testing.T) {
	devs, _ := LoadPatrolDir("testdata/trabajo_20261104-100000")
	g := Build(devs, nil, "")
	es, en := g.TextIn("es"), g.TextIn("en")
	if es != g.Text() || !strings.Contains(es, "Topología: 4 equipos, 4 enlaces") || !strings.Contains(es, "Hallazgos:") || !strings.Contains(es, "VLAN nativa distinta") || !strings.Contains(es, "root STP en") {
		t.Fatalf("es:\n%s", es)
	}
	for _, w := range []string{"Topología", "Enlaces", "Equipos", "Hallazgos", "root STP en", "VLAN nativa", "duplex distinto", "solo lo ve", "miembros hacia"} {
		if strings.Contains(en, w) {
			t.Fatalf("en trae %q:\n%s", w, en)
		}
	}
	if !strings.Contains(en, "Topology: 4 devices, 4 links") || !strings.Contains(en, "native VLAN mismatch") || !strings.Contains(en, "STP root on") {
		t.Fatalf("en:\n%s", en)
	}
	for _, f := range g.Findings {
		if f.Text == "" || f.TextTx.Empty() {
			t.Fatalf("hallazgo sin texto: %+v", f)
		}
	}
}

// cdpDe arma un "show cdp neighbors detail" donde el equipo ve a cada vecino por lif y ellos anuncian rif.
func cdpDe(lif, rif string, vecinos ...string) string {
	var sb strings.Builder
	for _, v := range vecinos {
		sb.WriteString("-------------------------\nDevice ID: " + v + "\nPlatform: cisco IOSv,  Capabilities: Router \nInterface: " + lif + ",  Port ID (outgoing port): " + rif + "\nHoldtime : 150 sec\n\n")
	}
	return sb.String()
}

func labCML(orden []string) []Device {
	var devs []Device
	for _, n := range orden {
		var otros []string
		for _, o := range []string{"R1", "R2", "R3", "R4", "R5"} {
			if o != n {
				otros = append(otros, o)
			}
		}
		out := cdpDe("Ethernet0/0", "Ethernet0/0", otros...)
		// punto a punto R1-R2 por Et0/1
		switch n {
		case "R1":
			out += cdpDe("Ethernet0/1", "Ethernet0/1", "R2")
		case "R2":
			out += cdpDe("Ethernet0/1", "Ethernet0/1", "R1")
		}
		devs = append(devs, Device{Name: n, Outputs: map[string]string{"show cdp neighbors detail": out}})
	}
	return devs
}

func TestSegmentoCompartido(t *testing.T) {
	g := Build(labCML([]string{"R1", "R2", "R3", "R4", "R5"}), nil, "")
	segs, alSeg, p2p := 0, 0, 0
	for _, n := range g.Nodes {
		if n.Kind == KindSegment {
			segs++
			if n.Collected || n.Name != "segmento compartido (5 equipos)" {
				t.Fatalf("segmento = %+v", n)
			}
		}
	}
	for _, l := range g.Links {
		if strings.HasPrefix(l.B, "seg:") {
			alSeg++
			if l.AIf != "Eth0/0" || len(l.Sources) != 1 || l.Sources[0] != "cdp" {
				t.Fatalf("enlace al segmento = %+v", l)
			}
		} else {
			p2p++
		}
	}
	if segs != 1 || alSeg != 5 || p2p != 1 || len(g.Links) != 6 || len(g.Findings) != 0 {
		t.Fatalf("segs=%d alSeg=%d p2p=%d findings=%+v\n%s", segs, alSeg, p2p, g.Findings, g.Text())
	}
	if !strings.Contains(g.SVG(), "<ellipse") {
		t.Fatal("el SVG no dibuja el segmento")
	}
}

func TestSegmentoIDEstable(t *testing.T) {
	id := func(g Graph) string {
		for _, n := range g.Nodes {
			if n.Kind == KindSegment {
				return n.ID
			}
		}
		return ""
	}
	a := id(Build(labCML([]string{"R1", "R2", "R3", "R4", "R5"}), nil, ""))
	b := id(Build(labCML([]string{"R5", "R3", "R1", "R4", "R2"}), nil, ""))
	if a == "" || a != b || a != "seg:r1|Eth0/0" {
		t.Fatalf("ids: %q %q", a, b)
	}
}

func TestDosVecinosNoSonSegmento(t *testing.T) {
	g := Build([]Device{
		{Name: "R1", Outputs: map[string]string{"show cdp neighbors detail": cdpDe("Ethernet0/0", "Ethernet0/0", "R2")}},
		{Name: "R2", Outputs: map[string]string{"show cdp neighbors detail": cdpDe("Ethernet0/0", "Ethernet0/0", "R1")}},
	}, nil, "")
	if len(g.Nodes) != 2 || len(g.Links) != 1 {
		t.Fatalf("grafo = %s", g.Text())
	}
}

// Los vecinos no se recolectaron: aun así R1 ve 3 por la misma interfaz.
func TestSegmentoConVecinosSinRecolectar(t *testing.T) {
	g := Build([]Device{{Name: "R1", Outputs: map[string]string{"show cdp neighbors detail": cdpDe("Ethernet0/0", "Ethernet0/0", "A", "B", "C")}}}, nil, "")
	if len(g.Nodes) != 5 || len(g.Links) != 4 {
		t.Fatalf("grafo = %s", g.Text())
	}
	if len(g.Findings) != 0 {
		t.Fatalf("hallazgos = %+v", g.Findings)
	}
}

func TestTextInSegmento(t *testing.T) {
	g := Build(labCML([]string{"R1", "R2", "R3", "R4", "R5"}), nil, "")
	es, en := g.TextIn("es"), g.TextIn("en")
	if !strings.Contains(es, "segmento compartido (5 equipos)") || !strings.Contains(es, "miembros: ") {
		t.Fatalf("es:\n%s", es)
	}
	if !strings.Contains(en, "shared segment (5 devices)") || !strings.Contains(en, "members: ") || strings.Contains(en, "segmento") || strings.Contains(en, "miembros") {
		t.Fatalf("en:\n%s", en)
	}
}

// Con 2 vecinos por la misma interfaz sigue habiendo enlaces punto a punto.
func TestDosVecinosPorInterfazNoSonSegmento(t *testing.T) {
	g := Build([]Device{{Name: "R1", Outputs: map[string]string{"show cdp neighbors detail": cdpDe("Ethernet0/0", "Ethernet0/0", "A", "B")}}}, nil, "")
	if len(g.Nodes) != 3 || len(g.Links) != 2 {
		t.Fatalf("grafo = %s", g.Text())
	}
}
