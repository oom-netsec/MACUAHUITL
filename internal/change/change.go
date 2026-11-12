// Package change compara la captura PRE y la POST de una ventana de cambio
// (recolectadas por Patrol con el playbook ios-xe/pre-post) y da un semáforo por
// equipo: sin cambios inesperados, revisar o regresión.
//
// Interpretación de salidas según la documentación pública de Cisco IOS-XE; sin
// validar en laboratorio.
//
// No hace: recolectar (eso es Patrol) ni aplicar configuración.
package change

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

// Level es el nivel de un hallazgo y también el semáforo del equipo (el peor de sus hallazgos).
type Level string

const (
	OK         Level = "ok"         // semáforo: sin cambios inesperados
	Info       Level = "info"       // esperado o informativo; no cambia el semáforo
	Review     Level = "review"     // revisar
	Regression Level = "regression" // algo que funcionaba dejó de funcionar
)

type Finding struct {
	Facet  string `json:"facet"`
	Level  Level  `json:"level"`
	Detail string `json:"detail"`
	// DetailTx es Detail como texto de catálogo (es/en); no viaja en el JSON.
	DetailTx i18n.Text `json:"-"`
}

// finding arma un hallazgo con su texto de catálogo (change.detail.*).
func finding(facet string, l Level, key string, kv ...any) Finding {
	t := i18n.Tx("change.detail."+key, kv...)
	return Finding{facet, l, t.In(i18n.Es), t}
}

type Device struct {
	Address    string    `json:"address"`
	Hostname   string    `json:"hostname"`
	Verdict    Level     `json:"verdict"`
	Findings   []Finding `json:"findings"`
	ConfigDiff []string  `json:"config_diff"` // "+ sección > línea" / "- sección > línea"
	// ConfigDiffTx marca con texto de catálogo la línea de aviso "… N líneas más" (mismo largo; el resto, vacío).
	ConfigDiffTx []i18n.Text `json:"-"`
}

type Report struct {
	Devices []Device  `json:"devices"`
	Note    string    `json:"note"`
	NoteTx  i18n.Text `json:"-"`
}

var noteTx = i18n.Tx("change.note")

// macDrop: una caída de MAC/ARP por debajo del 90 % se marca para revisar; las tablas fluctúan solas.
const macDrop = 0.9

const maxDiff = 500

// Compare empareja equipos por dirección. Uno que falta en POST o cuya captura POST falló es regresión.
func Compare(pre, post []capture.Device) Report {
	r := Report{Note: noteTx.In(i18n.Es), NoteTx: noteTx}
	byAddr := map[string]capture.Device{}
	for _, d := range post {
		byAddr[d.Address] = d
	}
	seen := map[string]bool{}
	for _, a := range pre {
		seen[a.Address] = true
		b, ok := byAddr[a.Address]
		d := Device{Address: a.Address, Hostname: a.Hostname, ConfigDiff: []string{}}
		switch {
		case !ok:
			d.Findings = []Finding{finding("captura", Regression, "no_post")}
		case b.State != "completed":
			d.Findings = []Finding{finding("captura", Regression, "post_failed", "detail", b.Detail)}
		case a.State != "completed":
			d.Findings = []Finding{finding("captura", Review, "pre_failed", "detail", a.Detail)}
			fallthrough
		default:
			if ok && b.State == "completed" {
				fs, diff, tx := compareDevice(Parse(a.Outputs), Parse(b.Outputs))
				d.Findings, d.ConfigDiff, d.ConfigDiffTx = append(d.Findings, fs...), diff, tx
			}
		}
		r.Devices = append(r.Devices, finish(d))
	}
	for _, b := range post {
		if !seen[b.Address] {
			r.Devices = append(r.Devices, finish(Device{Address: b.Address, Hostname: b.Hostname, ConfigDiff: []string{},
				Findings: []Finding{finding("captura", Review, "no_pre")}}))
		}
	}
	return r
}

func finish(d Device) Device {
	d.Verdict = OK
	for _, f := range d.Findings {
		switch {
		case f.Level == Regression:
			d.Verdict = Regression
		case f.Level == Review && d.Verdict == OK:
			d.Verdict = Review
		}
	}
	if d.Findings == nil {
		d.Findings = []Finding{}
	}
	return d
}

func compareDevice(a, b Snapshot) ([]Finding, []string, []i18n.Text) {
	var out []Finding
	add := func(facet string, l Level, key string, kv ...any) { out = append(out, finding(facet, l, key, kv...)) }
	for _, f := range []string{"versión", "config", "interfaces", "cdp", "lldp", "ospf", "bgp", "rutas", "mac", "arp", "hsrp", "stp"} {
		if a.Have[f] && !b.Have[f] {
			add(f, Review, "missing_post", "cmd", facetCmd[f])
		}
	}
	both := func(f string) bool { return a.Have[f] && b.Have[f] }
	if len(a.Have) == 0 {
		add("captura", Review, "no_pre_data")
	}
	if len(b.Have) == 0 {
		add("captura", Review, "no_post_data")
	}

	if both("versión") {
		if a.Version != b.Version {
			add("versión", Info, "version", "from", a.Version, "to", b.Version)
		}
		if a.UptimeMinutes >= 0 && b.UptimeMinutes >= 0 && b.UptimeMinutes < a.UptimeMinutes {
			add("versión", Review, "reloaded", "min", b.UptimeMinutes)
		}
	}
	if both("interfaces") {
		for _, k := range keys(a.Interfaces, b.Interfaces) {
			pa, pb := a.Interfaces[k], b.Interfaces[k]
			switch {
			case pa == "up/up" && pb == "":
				add("interfaces", Regression, "iface_gone", "name", k)
			case pa == "up/up" && pb != "up/up":
				add("interfaces", Regression, "iface_down", "name", k, "to", pb)
			case pa != "up/up" && pb == "up/up":
				if pa == "" {
					add("interfaces", Info, "iface_new", "name", k)
				} else {
					add("interfaces", Info, "iface_up", "name", k, "from", pa)
				}
			}
		}
	}
	for _, f := range []struct {
		name string
		a, b map[string]string
	}{{"cdp", a.CDP, b.CDP}, {"lldp", a.LLDP, b.LLDP}} {
		if both(f.name) {
			for _, k := range keys(f.a, f.b) {
				_, inA := f.a[k]
				_, inB := f.b[k]
				switch {
				case inA && !inB:
					add(f.name, Regression, "nbr_lost", "name", k, "port", f.a[k])
				case !inA && inB:
					add(f.name, Info, "nbr_new", "name", k, "port", f.b[k])
				case f.a[k] != f.b[k]:
					add(f.name, Review, "nbr_port", "name", k, "from", f.a[k], "to", f.b[k])
				}
			}
		}
	}
	if both("ospf") {
		for _, k := range keys(a.OSPF, b.OSPF) {
			sa, sb := a.OSPF[k], b.OSPF[k]
			switch {
			case sa != "" && sb == "":
				add("ospf", Regression, "ospf_lost", "name", k, "state", sa)
			case sa == "FULL" && sb != "FULL", sa == "2WAY" && sb != "FULL" && sb != "2WAY":
				add("ospf", Regression, "state", "name", k, "from", sa, "to", sb)
			case sa == "" && sb != "":
				add("ospf", Info, "ospf_new", "name", k, "state", sb)
			case sa != sb:
				add("ospf", Review, "state", "name", k, "from", sa, "to", sb)
			}
		}
	}
	if both("bgp") {
		for _, k := range keys(a.BGP, b.BGP) {
			sa, sb := a.BGP[k], b.BGP[k]
			switch {
			case sa == "Established" && sb != "Established":
				if sb == "" {
					add("bgp", Regression, "bgp_gone", "name", k)
				} else {
					add("bgp", Regression, "bgp_down", "name", k, "state", sb)
				}
			case sa == "" && sb != "":
				add("bgp", Info, "bgp_new", "name", k, "state", sb)
			case sa != "Established" && sb == "Established":
				add("bgp", Info, "bgp_up", "name", k, "state", sa)
			case sa == "Established" && drop(a.BGPPfx[k], b.BGPPfx[k]):
				add("bgp", Review, "bgp_prefixes", "name", k, "from", a.BGPPfx[k], "to", b.BGPPfx[k])
			}
		}
	}
	if both("rutas") {
		for _, k := range keys(a.Routes, b.Routes) {
			na, nb := a.Routes[k], b.Routes[k]
			switch {
			case na > 0 && nb == 0:
				add("rutas", Regression, "routes_zero", "name", k, "from", na)
			case nb < na:
				add("rutas", Review, "routes", "name", k, "from", na, "to", nb)
			case nb > na:
				add("rutas", Info, "routes", "name", k, "from", na, "to", nb)
			}
		}
	}
	counts := func(facet, key string, ma, mb map[string]int) {
		if !both(facet) {
			return
		}
		for _, k := range keys(ma, mb) {
			if drop(ma[k], mb[k]) {
				add(facet, Review, key, "name", k, "from", ma[k], "to", mb[k])
			}
		}
	}
	counts("mac", "mac_drop", a.MACs, b.MACs)
	counts("arp", "arp_drop", a.ARP, b.ARP)
	if both("hsrp") {
		for _, k := range keys(a.HSRP, b.HSRP) {
			sa, sb := a.HSRP[k], b.HSRP[k]
			switch {
			case sa != "" && sb == "":
				add("hsrp", Regression, "hsrp_gone", "name", k, "state", sa)
			case sa != sb && (sb == "Init" || sb == "Listen"):
				if sa == "" {
					add("hsrp", Regression, "hsrp_new", "name", k, "to", sb)
				} else {
					add("hsrp", Regression, "state", "name", k, "from", sa, "to", sb)
				}
			case sa != sb:
				if sa == "" {
					add("hsrp", Review, "hsrp_new", "name", k, "to", sb)
				} else {
					add("hsrp", Review, "state", "name", k, "from", sa, "to", sb)
				}
			}
		}
	}
	if both("stp") {
		for _, k := range keys(a.STPRoot, b.STPRoot) {
			ra, rb := a.STPRoot[k], b.STPRoot[k]
			switch {
			case ra != "" && rb == "":
				add("stp", Review, "stp_gone", "name", k)
			case ra != "" && ra != rb:
				add("stp", Regression, "stp_root", "name", k, "from", ra, "to", rb)
			case ra == "" && rb != "":
				add("stp", Info, "stp_new", "name", k, "root", rb)
			case a.STPPort[k] != b.STPPort[k]:
				out = append(out, stpPort(k, a.STPPort[k], b.STPPort[k]))
			}
		}
	}
	var diff []string
	var tx []i18n.Text
	if both("config") {
		diff = configDiff(a.Config, b.Config)
		added, removed := 0, 0
		for _, d := range diff {
			if strings.HasPrefix(d, "+") {
				added++
			} else {
				removed++
			}
		}
		if len(diff) > 0 {
			add("config", Info, "config", "added", added, "removed", removed)
		}
		if len(diff) > maxDiff {
			more := i18n.Tx("change.diff.more", "n", len(diff)-maxDiff)
			diff = append(diff[:maxDiff], more.In(i18n.Es))
			tx = make([]i18n.Text, len(diff))
			tx[len(diff)-1] = more
		}
	}
	return out, diff, tx
}

// drop: bajó de un valor positivo a menos del 90 %.
func drop(a, b int) bool { return a > 0 && float64(b) < float64(a)*macDrop }

// volatile: líneas que cambian solas sin que nadie toque la configuración.
var volatile = regexp.MustCompile(`^ntp clock-period \d+$`)

// configDiff compara por ruta jerárquica: reordenar secciones no cuenta como cambio.
func configDiff(a, b *iosconf.Node) []string {
	paths := func(n *iosconf.Node) map[string]int {
		m := map[string]int{}
		n.Walk(func(x *iosconf.Node) {
			if !volatile.MatchString(x.Line) {
				m[x.Path()]++
			}
		})
		return m
	}
	pa, pb := paths(a), paths(b)
	var out []string
	for _, p := range keys(pa, pb) {
		for i := pb[p]; i < pa[p]; i++ {
			out = append(out, "- "+p)
		}
		for i := pa[p]; i < pb[p]; i++ {
			out = append(out, "+ "+p)
		}
	}
	return out
}

func keys[V any](a, b map[string]V) []string {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// stpPort es el hallazgo del cambio de puerto raíz; un puerto vacío se dice «ninguno».
func stpPort(name, from, to string) Finding {
	port := func(p string) i18n.Text {
		if p == "" {
			return i18n.Tx("change.word.none")
		}
		return i18n.Lit(p, p)
	}
	t := i18n.Tx("change.detail.stp_port", "name", name).With("from", port(from)).With("to", port(to))
	return Finding{"stp", Review, t.In(i18n.Es), t}
}

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Text es el informe legible, en español.
func (r Report) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el informe en el idioma pedido (con es, el de siempre). Los hallazgos y la nota ya vienen en ese
// idioma si el informe pasó por i18n.Localize.
func (r Report) TextIn(loc string) string {
	var b strings.Builder
	m := func(key string) string { return i18n.Msg(loc, key, nil) }
	for _, d := range r.Devices {
		fmt.Fprintf(&b, "%s (%s): %s\n", or(d.Hostname, "?"), d.Address, m("change.text.verdict."+string(d.Verdict)))
		for _, f := range d.Findings {
			fmt.Fprintf(&b, "  %-10s %-10s %s\n", m("change.text.level."+string(f.Level)), f.Facet, f.Detail)
		}
		for _, l := range d.ConfigDiff {
			b.WriteString("    " + l + "\n")
		}
	}
	b.WriteString(r.Note + "\n")
	return b.String()
}
