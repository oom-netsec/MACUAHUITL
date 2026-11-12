package analyze

import (
	"fmt"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

type CounterDelta struct {
	Interface string `json:"interface"`
	Counter   string `json:"counter"`
	From      int64  `json:"from"`
	To        int64  `json:"to"`
	Delta     int64  `json:"delta"`
}

type NeighborChange struct {
	Protocol string `json:"protocol"` // bgp, ospf, hsrp
	ID       string `json:"id"`
	Change   string `json:"change"` // apareció, desapareció, cambió
	From     string `json:"from"`
	To       string `json:"to"`
}

type PrefixChange struct {
	Neighbor string `json:"neighbor"`
	From     int    `json:"from"`
	To       int    `json:"to"`
}

type UptimeChange struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Reset bool   `json:"reset"`
}

// TextDiff es el respaldo línea a línea de un comando: "- " sale, "+ " entra.
type TextDiff struct {
	Command string    `json:"command"`
	Lines   []string  `json:"lines"`
	Note    string    `json:"note,omitempty"`
	NoteTx  i18n.Text `json:"-"`
}

type DeviceDiff struct {
	Device    string           `json:"device"`
	Counters  []CounterDelta   `json:"counters"`
	Neighbors []NeighborChange `json:"neighbors"`
	Prefixes  []PrefixChange   `json:"prefixes"`
	Uptime    *UptimeChange    `json:"uptime,omitempty"`
	Text      []TextDiff       `json:"text"`
}

type DiffReport struct {
	Dir      string       `json:"dir"`
	From     int          `json:"from"`
	To       int          `json:"to"`
	Devices  []DeviceDiff `json:"devices"`
	Warnings []Warning    `json:"warnings"`
}

// Diff compara la ronda from con la to, por equipo.
func Diff(b *Bundle, from, to int, device string) (DiffReport, error) {
	r := DiffReport{Dir: b.Dir, From: from, To: to, Devices: []DeviceDiff{}, Warnings: append([]Warning{}, b.Warnings...)}
	rounds := map[int]bool{}
	for _, n := range b.Rounds("") {
		rounds[n] = true
	}
	if !rounds[from] || !rounds[to] {
		return r, fmt.Errorf("analyze: el trabajo tiene las rondas %v; no hay %d o %d", b.Rounds(""), from, to)
	}
	for _, dev := range b.Devices() {
		if !matchDevice(dev, device) {
			continue
		}
		a, z := byCommand(b, dev, from), byCommand(b, dev, to)
		if len(a) == 0 || len(z) == 0 {
			r.Warnings = append(r.Warnings, Warn(dev, 0, "", "analyze.warn.no_outputs", "from", from, "to", to))
			continue
		}
		d := DeviceDiff{Device: dev, Counters: []CounterDelta{}, Neighbors: []NeighborChange{}, Prefixes: []PrefixChange{}, Text: []TextDiff{}}
		diffInterfaces(&d, a["show interfaces"], z["show interfaces"])
		diffUptime(&d, a["show version"], z["show version"])
		diffBGP(&d, firstOf(a, "show ip bgp summary", "show bgp summary", "show bgp ipv4 unicast summary", "show bgp ipv6 unicast summary"), firstOf(z, "show ip bgp summary", "show bgp summary", "show bgp ipv4 unicast summary", "show bgp ipv6 unicast summary"))
		diffOSPF(&d, a["show ip ospf neighbor"], z["show ip ospf neighbor"])
		diffHSRP(&d, a["show standby brief"], z["show standby brief"])
		for _, cmd := range sortedKeys(union(a, z)) {
			x, okx := a[cmd]
			y, oky := z[cmd]
			switch {
			case !okx:
				n := i18n.Tx("analyze.diff.only_in", "round", to)
				d.Text = append(d.Text, TextDiff{Command: cmd, Lines: []string{}, Note: n.In(i18n.Es), NoteTx: n})
			case !oky:
				n := i18n.Tx("analyze.diff.only_in", "round", from)
				d.Text = append(d.Text, TextDiff{Command: cmd, Lines: []string{}, Note: n.In(i18n.Es), NoteTx: n})
			case x != y:
				ls, note := lineDiff(lines(x), lines(y))
				d.Text = append(d.Text, TextDiff{Command: cmd, Lines: ls, Note: note.In(i18n.Es), NoteTx: note})
			}
		}
		r.Devices = append(r.Devices, d)
	}
	return r, nil
}

// byCommand: texto de cada comando válido de la ronda, con el nombre normalizado.
func byCommand(b *Bundle, dev string, round int) map[string]string {
	out := map[string]string{}
	for _, s := range b.Sections {
		if s.Device == dev && s.Round == round && !s.Invalid {
			if _, ok := out[normCmd(s.Command)]; !ok {
				out[normCmd(s.Command)] = s.Text
			}
		}
	}
	return out
}

func firstOf(m map[string]string, cmds ...string) string {
	for _, c := range cmds {
		if t, ok := m[c]; ok {
			return t
		}
	}
	return ""
}

func union(a, b map[string]string) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func diffInterfaces(d *DeviceDiff, a, z string) {
	ia, ok1 := parseInterfaces(a)
	iz, ok2 := parseInterfaces(z)
	if !ok1 || !ok2 {
		return
	}
	prev := map[string]ifaceCounters{}
	for _, i := range ia {
		prev[i.Name] = i
	}
	for _, i := range iz {
		p, ok := prev[i.Name]
		if !ok {
			continue
		}
		for _, c := range CounterNames {
			x, ok1 := p.Values[c]
			y, ok2 := i.Values[c]
			if ok1 && ok2 && x != y {
				d.Counters = append(d.Counters, CounterDelta{Interface: i.Name, Counter: c, From: x, To: y, Delta: y - x})
			}
		}
	}
}

func diffUptime(d *DeviceDiff, a, z string) {
	ua, ok1 := parseUptime(a)
	uz, ok2 := parseUptime(z)
	if ok1 && ok2 {
		d.Uptime = &UptimeChange{From: fmtDur(ua.D), To: fmtDur(uz.D), Reset: uz.D < ua.D}
	}
}

// states compara dos mapas id → estado y anota lo que aparece, desaparece o cambia.
func states(d *DeviceDiff, proto string, a, z map[string]string) {
	for _, id := range sortedKeys(union(a, z)) {
		x, okx := a[id]
		y, oky := z[id]
		switch {
		case !okx:
			d.Neighbors = append(d.Neighbors, NeighborChange{Protocol: proto, ID: id, Change: "apareció", To: y})
		case !oky:
			d.Neighbors = append(d.Neighbors, NeighborChange{Protocol: proto, ID: id, Change: "desapareció", From: x})
		case x != y:
			d.Neighbors = append(d.Neighbors, NeighborChange{Protocol: proto, ID: id, Change: "cambió", From: x, To: y})
		}
	}
}

func diffBGP(d *DeviceDiff, a, z string) {
	na, ok1 := iosxe.ParseBGP(a)
	nz, ok2 := iosxe.ParseBGP(z)
	if !ok1 || !ok2 || a == "" || z == "" {
		return
	}
	sa, sz := map[string]string{}, map[string]string{}
	pfx := map[string]int{}
	for _, n := range na {
		sa[n.ID] = n.State
		if n.Established {
			pfx[n.ID] = n.Prefixes
		}
	}
	for _, n := range nz {
		sz[n.ID] = n.State
		if p, ok := pfx[n.ID]; ok && n.Established && p != n.Prefixes {
			d.Prefixes = append(d.Prefixes, PrefixChange{Neighbor: n.ID, From: p, To: n.Prefixes})
		}
	}
	states(d, "bgp", sa, sz)
}

func diffOSPF(d *DeviceDiff, a, z string) {
	na, ok1 := iosxe.ParseOSPF(a)
	nz, ok2 := iosxe.ParseOSPF(z)
	if !ok1 || !ok2 || a == "" || z == "" {
		return
	}
	sa, sz := map[string]string{}, map[string]string{}
	for _, n := range na {
		sa[ospfKey(n)] = n.State
	}
	for _, n := range nz {
		sz[ospfKey(n)] = n.State
	}
	states(d, "ospf", sa, sz)
}

func diffHSRP(d *DeviceDiff, a, z string) {
	ga, ok1 := iosxe.ParseHSRP(a)
	gz, ok2 := iosxe.ParseHSRP(z)
	if !ok1 || !ok2 || a == "" || z == "" {
		return
	}
	sa, sz := map[string]string{}, map[string]string{}
	for _, g := range ga {
		sa[hsrpKey(g)] = g.State
	}
	for _, g := range gz {
		sz[hsrpKey(g)] = g.State
	}
	states(d, "hsrp", sa, sz)
}

const (
	maxDiffCells = 4_000_000 // tabla LCS: ~16 MB como máximo
	maxDiffLines = 400
)

// lineDiff da las líneas que salen ("- ") y entran ("+ ") por LCS, sin contexto.
func lineDiff(a, b []string) ([]string, i18n.Text) {
	for len(a) > 0 && len(b) > 0 && a[0] == b[0] {
		a, b = a[1:], b[1:]
	}
	for len(a) > 0 && len(b) > 0 && a[len(a)-1] == b[len(b)-1] {
		a, b = a[:len(a)-1], b[:len(b)-1]
	}
	if len(a)*len(b) > maxDiffCells {
		return []string{}, i18n.Tx("analyze.diff.too_big", "a", len(a), "b", len(b))
	}
	// lcs[i][j] = longitud de la LCS de a[i:] y b[j:].
	lcs := make([][]int32, len(a)+1)
	for i := range lcs {
		lcs[i] = make([]int32, len(b)+1)
	}
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	out := []string{}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case i < len(a) && j < len(b) && a[i] == b[j]:
			i, j = i+1, j+1
		case i < len(a) && (j == len(b) || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, "- "+a[i])
			i++
		default:
			out = append(out, "+ "+b[j])
			j++
		}
	}
	var note i18n.Text
	if len(out) > maxDiffLines {
		note = i18n.Tx("analyze.diff.more_lines", "n", len(out)-maxDiffLines)
		out = out[:maxDiffLines]
	}
	return out, note
}

// Text es el resumen legible para mctl, en español.
func (r DiffReport) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el resumen en el idioma pedido (con es, el de siempre).
func (r DiffReport) TextIn(loc string) string {
	var b strings.Builder
	m := func(key string, kv ...any) string { return i18n.Msg(loc, key, i18n.A(kv...)) }
	fmt.Fprintf(&b, "%s\n%s\n", r.Dir, m("analyze.text.rounds", "from", r.From, "to", r.To))
	for _, d := range r.Devices {
		fmt.Fprintf(&b, "\n== %s ==\n", d.Device)
		if d.Uptime != nil {
			reset := ""
			if d.Uptime.Reset {
				reset = m("analyze.text.reload")
			}
			fmt.Fprintf(&b, "uptime: %s → %s%s\n", d.Uptime.From, d.Uptime.To, reset)
		}
		for _, c := range d.Counters {
			fmt.Fprintf(&b, "%s\n", m("analyze.text.counter", "iface", c.Interface, "counter", c.Counter, "from", c.From, "to", c.To, "delta", fmt.Sprintf("%+d", c.Delta)))
		}
		for _, n := range d.Neighbors {
			fmt.Fprintf(&b, "%s %s %s %s\n", n.Protocol, n.ID, n.Change, strings.Trim(n.From+" → "+n.To, " →"))
		}
		for _, p := range d.Prefixes {
			fmt.Fprintf(&b, "%s\n", m("analyze.text.prefixes", "neighbor", p.Neighbor, "from", p.From, "to", p.To))
		}
		for _, t := range d.Text {
			fmt.Fprintf(&b, "--- %s", t.Command)
			if t.Note != "" {
				fmt.Fprintf(&b, " (%s)", t.Note)
			}
			b.WriteString("\n")
			for _, ln := range t.Lines {
				fmt.Fprintf(&b, "  %s\n", ln)
			}
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "%s\n", m("analyze.text.warning", "message", w.in(loc)))
	}
	return b.String()
}
