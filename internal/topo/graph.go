package topo

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"
)

// Lienzo del dibujo; X e Y de cada nodo caen dentro.
const (
	Width  = 960.0
	Height = 640.0
)

type Node struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Platform  string  `json:"platform,omitempty"`
	MgmtIP    string  `json:"mgmt_ip,omitempty"`
	Version   string  `json:"version,omitempty"`
	Collected bool    `json:"collected"` // hay salidas CDP/LLDP propias (Patrol) o es el punto de captura
	RootVLANs []int   `json:"root_vlans,omitempty"`
	X         float64 `json:"x"`
	Y         float64 `json:"y"`
}

// Link es un enlace entre dos interfaces. Los campos B* describen el puerto de B
// tal como lo anuncia B (visto desde A) y viceversa.
type Link struct {
	A           string   `json:"a"`
	AIf         string   `json:"a_if"`
	B           string   `json:"b"`
	BIf         string   `json:"b_if"`
	Sources     []string `json:"sources"` // cdp, lldp, pcap
	SeenBy      []string `json:"seen_by"` // nodos que reportaron el enlace
	ANativeVLAN string   `json:"a_native_vlan,omitempty"`
	BNativeVLAN string   `json:"b_native_vlan,omitempty"`
	ADuplex     string   `json:"a_duplex,omitempty"`
	BDuplex     string   `json:"b_duplex,omitempty"`
}

func (l Link) vlanMismatch() bool {
	return l.ANativeVLAN != "" && l.BNativeVLAN != "" && l.ANativeVLAN != l.BNativeVLAN
}

func (l Link) duplexMismatch() bool {
	return l.ADuplex != "" && l.BDuplex != "" && l.ADuplex != l.BDuplex
}

type Finding struct {
	Kind     string `json:"kind"` // one_sided, native_vlan, duplex, port_channel
	Severity string `json:"severity"`
	Text     string `json:"text"`
}

type Graph struct {
	Nodes    []Node    `json:"nodes"`
	Links    []Link    `json:"links"`
	Findings []Finding `json:"findings"`
}

func (g *Graph) node(id string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

// nodeID canoniza el nombre: sin serie de NX-OS ("N9K-1(FDO…)") ni dominio, en minúsculas.
func nodeID(name string) string {
	s := strings.TrimSpace(name)
	if i := strings.IndexByte(s, '('); i > 0 && strings.HasSuffix(s, ")") {
		s = s[:i]
	}
	if _, err := netip.ParseAddr(s); err != nil {
		s, _, _ = strings.Cut(s, ".")
	}
	return strings.ToLower(s)
}

type builder struct {
	g     Graph
	byIP  map[string]string
	links map[string]*Link
}

func (b *builder) add(name, ip string) *Node {
	id := nodeID(name)
	if ip != "" && b.byIP[ip] != "" {
		id = b.byIP[ip]
	}
	n := b.g.node(id)
	if n == nil {
		b.g.Nodes = append(b.g.Nodes, Node{ID: id, Name: displayName(name)})
		n = &b.g.Nodes[len(b.g.Nodes)-1]
	}
	if ip != "" {
		b.byIP[ip] = id
		if n.MgmtIP == "" {
			n.MgmtIP = ip
		}
	}
	return n
}

func displayName(s string) string {
	if i := strings.IndexByte(s, '('); i > 0 && strings.HasSuffix(s, ")") {
		return s[:i]
	}
	return s
}

func fill(dst *string, v string) {
	if *dst == "" {
		*dst = v
	}
}

// observe registra que local ve a n por localIf.
func (b *builder) observe(local string, n iosxe.Neighbor, source string) {
	remote := b.add(n.Device, n.MgmtIP)
	fill(&remote.Platform, n.Platform)
	fill(&remote.Version, n.Version)
	ai, bi := iosxe.ShortIf(n.LocalIf), iosxe.ShortIf(n.RemoteIf)
	a, bn := local, remote.ID
	flip := a > bn || (a == bn && ai > bi)
	if flip {
		a, bn, ai, bi = bn, a, bi, ai
	}
	k := a + "|" + ai + "|" + bn + "|" + bi
	l := b.links[k]
	if l == nil {
		l = &Link{A: a, AIf: ai, B: bn, BIf: bi}
		b.links[k] = l
	}
	if !contains(l.Sources, source) {
		l.Sources = append(l.Sources, source)
	}
	if !contains(l.SeenBy, local) {
		l.SeenBy = append(l.SeenBy, local)
	}
	// Lo anunciado describe el puerto remoto.
	if flip {
		fill(&l.ANativeVLAN, n.NativeVLAN)
		fill(&l.ADuplex, strings.ToLower(n.Duplex))
	} else {
		fill(&l.BNativeVLAN, n.NativeVLAN)
		fill(&l.BDuplex, strings.ToLower(n.Duplex))
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// Build arma el grafo. pcapName nombra el punto de captura cuando hay vecinos de un PCAP.
func Build(devs []Device, pcapNeighbors []pcapan.Neighbor, pcapName string) Graph {
	b := &builder{byIP: map[string]string{}, links: map[string]*Link{}}
	type local struct {
		id  string
		dev Device
	}
	var locals []local
	// Primero los equipos recolectados, para que los vecinos se unan a ellos por IP.
	for _, d := range devs {
		n := b.add(d.Name, d.IP)
		n.Platform, n.Version = d.Platform, d.Version
		locals = append(locals, local{n.ID, d})
	}
	for _, l := range locals {
		cdp, _ := iosxe.ParseCDP(output(l.dev, "show cdp neighbors detail"))
		lldp, _ := iosxe.ParseLLDP(output(l.dev, "show lldp neighbors detail"))
		if len(cdp)+len(lldp) > 0 || output(l.dev, "show cdp neighbors detail") != "" || output(l.dev, "show lldp neighbors detail") != "" {
			b.g.node(l.id).Collected = true
		}
		for _, n := range cdp {
			b.observe(l.id, n, "cdp")
		}
		for _, n := range lldp {
			b.observe(l.id, n, "lldp")
		}
		b.g.node(l.id).RootVLANs = iosxe.ParseSTPRoots(output(l.dev, "show spanning-tree"))
	}
	if len(pcapNeighbors) > 0 {
		cap := b.add("captura "+pcapName, "")
		cap.Collected = true
		for _, p := range pcapNeighbors {
			n := iosxe.Neighbor{Device: p.DeviceID, RemoteIf: p.Port, Platform: p.Platform, MgmtIP: p.MgmtIP}
			if p.NativeVLAN != 0 {
				n.NativeVLAN = fmt.Sprint(p.NativeVLAN)
			}
			b.observe(cap.ID, n, "pcap")
		}
	}
	keys := make([]string, 0, len(b.links))
	for k := range b.links {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.g.Links = append(b.g.Links, *b.links[k])
	}
	for _, l := range locals {
		b.portChannels(l.id, iosxe.ParsePortChannels(firstOutput(l.dev, "show etherchannel summary", "show port-channel summary")))
	}
	b.checkLinks()
	layout(b.g.Nodes, b.g.Links)
	return b.g
}

func firstOutput(d Device, cmds ...string) string {
	for _, c := range cmds {
		if s := output(d, c); s != "" {
			return s
		}
	}
	return ""
}

func (b *builder) checkLinks() {
	for _, l := range b.g.Links {
		where := fmt.Sprintf("%s %s ↔ %s %s", b.g.node(l.A).Name, l.AIf, b.g.node(l.B).Name, l.BIf)
		if len(l.SeenBy) == 1 && b.g.node(l.A).Collected && b.g.node(l.B).Collected && !contains(l.Sources, "pcap") {
			other := l.A
			if l.SeenBy[0] == l.A {
				other = l.B
			}
			b.g.Findings = append(b.g.Findings, Finding{"one_sided", "warning",
				fmt.Sprintf("%s: solo lo ve un lado; %s no lo reporta (CDP/LLDP apagado en el puerto, enlace unidireccional o cableado distinto)", where, b.g.node(other).Name)})
		}
		if l.vlanMismatch() {
			b.g.Findings = append(b.g.Findings, Finding{"native_vlan", "error",
				fmt.Sprintf("%s: VLAN nativa distinta (%s vs %s)", where, l.ANativeVLAN, l.BNativeVLAN)})
		}
		if l.duplexMismatch() {
			b.g.Findings = append(b.g.Findings, Finding{"duplex", "error",
				fmt.Sprintf("%s: duplex distinto (%s vs %s)", where, l.ADuplex, l.BDuplex)})
		}
	}
}

// portChannels marca port-channels cuyos miembros llegan a vecinos distintos.
func (b *builder) portChannels(id string, pcs map[string][]string) {
	names := make([]string, 0, len(pcs))
	for k := range pcs {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, po := range names {
		members := map[string]bool{}
		for _, m := range pcs[po] {
			members[iosxe.ShortIf(m)] = true
		}
		var peers []string
		for _, l := range b.g.Links {
			peer := ""
			switch {
			case l.A == id && members[l.AIf]:
				peer = l.B
			case l.B == id && members[l.BIf]:
				peer = l.A
			}
			if peer != "" && !contains(peers, b.g.node(peer).Name) {
				peers = append(peers, b.g.node(peer).Name)
			}
		}
		if len(peers) > 1 {
			sort.Strings(peers)
			b.g.Findings = append(b.g.Findings, Finding{"port_channel", "warning",
				fmt.Sprintf("%s %s: miembros hacia vecinos distintos (%s); correcto solo con vPC, StackWise Virtual o MLAG", b.g.node(id).Name, po, strings.Join(peers, ", "))})
		}
	}
}

// layout es Fruchterman-Reingold determinista: arranca en círculo y hace 200 pasos.
func layout(nodes []Node, links []Link) {
	n := len(nodes)
	if n == 0 {
		return
	}
	idx := map[string]int{}
	for i := range nodes {
		idx[nodes[i].ID] = i
		a := 2 * math.Pi * float64(i) / float64(n)
		nodes[i].X, nodes[i].Y = Width/2+Width/3*math.Cos(a), Height/2+Height/3*math.Sin(a)
	}
	if n == 1 {
		nodes[0].X, nodes[0].Y = Width/2, Height/2
		return
	}
	k := math.Sqrt(Width * Height / float64(n))
	temp := Width / 10
	const margin = 60.0
	for it := 0; it < 200; it++ {
		dx, dy := make([]float64, n), make([]float64, n)
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				x, y := nodes[i].X-nodes[j].X, nodes[i].Y-nodes[j].Y
				d := math.Max(math.Hypot(x, y), 0.01)
				f := k * k / d
				dx[i] += x / d * f
				dy[i] += y / d * f
				dx[j] -= x / d * f
				dy[j] -= y / d * f
			}
		}
		for _, l := range links {
			i, j := idx[l.A], idx[l.B]
			if i == j {
				continue
			}
			x, y := nodes[i].X-nodes[j].X, nodes[i].Y-nodes[j].Y
			d := math.Max(math.Hypot(x, y), 0.01)
			f := d * d / k
			dx[i] -= x / d * f
			dy[i] -= y / d * f
			dx[j] += x / d * f
			dy[j] += y / d * f
		}
		for i := range nodes {
			d := math.Max(math.Hypot(dx[i], dy[i]), 0.01)
			nodes[i].X = math.Min(Width-margin, math.Max(margin, nodes[i].X+dx[i]/d*math.Min(d, temp)))
			nodes[i].Y = math.Min(Height-margin, math.Max(margin, nodes[i].Y+dy[i]/d*math.Min(d, temp)))
		}
		temp *= 0.97
	}
}

// Text es el resumen legible.
func (g Graph) Text() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Topología: %d equipos, %d enlaces\n\nEquipos:\n", len(g.Nodes), len(g.Links))
	for _, n := range g.Nodes {
		fmt.Fprintf(&sb, "  %-24s %-18s %-16s %s", n.Name, n.Platform, n.MgmtIP, n.Version)
		if len(n.RootVLANs) > 0 {
			fmt.Fprintf(&sb, "  root STP en %v", n.RootVLANs)
		}
		sb.WriteString("\n")
	}
	sb.WriteString("\nEnlaces:\n")
	for _, l := range g.Links {
		fmt.Fprintf(&sb, "  %s %s ↔ %s %s  [%s]\n", g.node(l.A).Name, l.AIf, g.node(l.B).Name, l.BIf, strings.Join(l.Sources, ","))
	}
	if len(g.Findings) > 0 {
		sb.WriteString("\nHallazgos:\n")
		for _, f := range g.Findings {
			fmt.Fprintf(&sb, "  [%s] %s\n", f.Severity, f.Text)
		}
	}
	return sb.String()
}
