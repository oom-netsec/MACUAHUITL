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
}

type Device struct {
	Address    string    `json:"address"`
	Hostname   string    `json:"hostname"`
	Verdict    Level     `json:"verdict"`
	Findings   []Finding `json:"findings"`
	ConfigDiff []string  `json:"config_diff"` // "+ sección > línea" / "- sección > línea"
}

type Report struct {
	Devices []Device `json:"devices"`
	Note    string   `json:"note"`
}

const note = "Comparación de salidas show; interpretación según la documentación pública de Cisco IOS-XE, sin validar en laboratorio. La app no aplica configuración."

// macDrop: una caída de MAC/ARP por debajo del 90 % se marca para revisar; las tablas fluctúan solas.
const macDrop = 0.9

const maxDiff = 500

// Compare empareja equipos por dirección. Uno que falta en POST o cuya captura POST falló es regresión.
func Compare(pre, post []capture.Device) Report {
	r := Report{Note: note}
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
			d.Findings = []Finding{{"captura", Regression, "no está en la captura POST"}}
		case b.State != "completed":
			d.Findings = []Finding{{"captura", Regression, "la captura POST falló: " + b.Detail}}
		case a.State != "completed":
			d.Findings = []Finding{{"captura", Review, "la captura PRE falló (" + a.Detail + "): no hay línea base completa"}}
			fallthrough
		default:
			if ok && b.State == "completed" {
				fs, diff := compareDevice(Parse(a.Outputs), Parse(b.Outputs))
				d.Findings, d.ConfigDiff = append(d.Findings, fs...), diff
			}
		}
		r.Devices = append(r.Devices, finish(d))
	}
	for _, b := range post {
		if !seen[b.Address] {
			r.Devices = append(r.Devices, finish(Device{Address: b.Address, Hostname: b.Hostname, ConfigDiff: []string{},
				Findings: []Finding{{"captura", Review, "no está en la captura PRE: sin línea base"}}}))
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

func compareDevice(a, b Snapshot) ([]Finding, []string) {
	var out []Finding
	add := func(facet string, l Level, format string, args ...any) {
		out = append(out, Finding{facet, l, fmt.Sprintf(format, args...)})
	}
	for _, f := range []string{"versión", "config", "interfaces", "cdp", "lldp", "ospf", "bgp", "rutas", "mac", "arp", "hsrp", "stp"} {
		if a.Have[f] && !b.Have[f] {
			add(f, Review, "sin salida de %q en POST: no se puede comparar", facetCmd[f])
		}
	}
	both := func(f string) bool { return a.Have[f] && b.Have[f] }
	if len(a.Have) == 0 {
		add("captura", Review, "sin salidas reconocidas en PRE: no hay línea base")
	}
	if len(b.Have) == 0 {
		add("captura", Review, "sin salidas reconocidas en POST: no se puede comparar")
	}

	if both("versión") {
		if a.Version != b.Version {
			add("versión", Info, "%s → %s", a.Version, b.Version)
		}
		if a.UptimeMinutes >= 0 && b.UptimeMinutes >= 0 && b.UptimeMinutes < a.UptimeMinutes {
			add("versión", Review, "el equipo se recargó entre PRE y POST (uptime %d min)", b.UptimeMinutes)
		}
	}
	if both("interfaces") {
		for _, k := range keys(a.Interfaces, b.Interfaces) {
			pa, pb := a.Interfaces[k], b.Interfaces[k]
			switch {
			case pa == "up/up" && pb == "":
				add("interfaces", Regression, "%s estaba up/up y ya no aparece", k)
			case pa == "up/up" && pb != "up/up":
				add("interfaces", Regression, "%s: up/up → %s", k, pb)
			case pa != "up/up" && pb == "up/up":
				add("interfaces", Info, "%s: %s → up/up", k, or(pa, "no existía"))
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
					add(f.name, Regression, "vecino perdido: %s (puerto %s)", k, f.a[k])
				case !inA && inB:
					add(f.name, Info, "vecino nuevo: %s (puerto %s)", k, f.b[k])
				case f.a[k] != f.b[k]:
					add(f.name, Review, "%s: puerto remoto %s → %s", k, f.a[k], f.b[k])
				}
			}
		}
	}
	if both("ospf") {
		for _, k := range keys(a.OSPF, b.OSPF) {
			sa, sb := a.OSPF[k], b.OSPF[k]
			switch {
			case sa != "" && sb == "":
				add("ospf", Regression, "adyacencia perdida: %s (estaba %s)", k, sa)
			case sa == "FULL" && sb != "FULL", sa == "2WAY" && sb != "FULL" && sb != "2WAY":
				add("ospf", Regression, "%s: %s → %s", k, sa, sb)
			case sa == "" && sb != "":
				add("ospf", Info, "adyacencia nueva: %s (%s)", k, sb)
			case sa != sb:
				add("ospf", Review, "%s: %s → %s", k, sa, sb)
			}
		}
	}
	if both("bgp") {
		for _, k := range keys(a.BGP, b.BGP) {
			sa, sb := a.BGP[k], b.BGP[k]
			switch {
			case sa == "Established" && sb != "Established":
				add("bgp", Regression, "vecino %s: Established → %s", k, or(sb, "ya no aparece"))
			case sa == "" && sb != "":
				add("bgp", Info, "vecino nuevo %s (%s)", k, sb)
			case sa != "Established" && sb == "Established":
				add("bgp", Info, "vecino %s: %s → Established", k, sa)
			case sa == "Established" && drop(a.BGPPfx[k], b.BGPPfx[k]):
				add("bgp", Review, "vecino %s: prefijos recibidos %d → %d", k, a.BGPPfx[k], b.BGPPfx[k])
			}
		}
	}
	if both("rutas") {
		for _, k := range keys(a.Routes, b.Routes) {
			na, nb := a.Routes[k], b.Routes[k]
			switch {
			case na > 0 && nb == 0:
				add("rutas", Regression, "%s: %d → 0 rutas", k, na)
			case nb < na:
				add("rutas", Review, "%s: %d → %d", k, na, nb)
			case nb > na:
				add("rutas", Info, "%s: %d → %d", k, na, nb)
			}
		}
	}
	counts := func(facet, label string, ma, mb map[string]int) {
		if !both(facet) {
			return
		}
		for _, k := range keys(ma, mb) {
			if drop(ma[k], mb[k]) {
				add(facet, Review, "%s%s: %d → %d", label, k, ma[k], mb[k])
			}
		}
	}
	counts("mac", "VLAN ", a.MACs, b.MACs)
	counts("arp", "", a.ARP, b.ARP)
	if both("hsrp") {
		for _, k := range keys(a.HSRP, b.HSRP) {
			sa, sb := a.HSRP[k], b.HSRP[k]
			switch {
			case sa != "" && sb == "":
				add("hsrp", Regression, "%s ya no aparece (estaba %s)", k, sa)
			case sa != sb && (sb == "Init" || sb == "Listen"):
				add("hsrp", Regression, "%s: %s → %s", k, or(sa, "no existía"), sb)
			case sa != sb:
				add("hsrp", Review, "%s: %s → %s", k, or(sa, "no existía"), sb)
			}
		}
	}
	if both("stp") {
		for _, k := range keys(a.STPRoot, b.STPRoot) {
			ra, rb := a.STPRoot[k], b.STPRoot[k]
			switch {
			case ra != "" && rb == "":
				add("stp", Review, "%s ya no aparece", k)
			case ra != "" && ra != rb:
				add("stp", Regression, "%s: raíz %s → %s", k, ra, rb)
			case ra == "" && rb != "":
				add("stp", Info, "%s nueva (raíz %s)", k, rb)
			case a.STPPort[k] != b.STPPort[k]:
				add("stp", Review, "%s: puerto raíz %s → %s", k, or(a.STPPort[k], "ninguno"), or(b.STPPort[k], "ninguno"))
			}
		}
	}
	var diff []string
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
			add("config", Info, "running-config: %d agregadas, %d quitadas", added, removed)
		}
		if len(diff) > maxDiff {
			diff = append(diff[:maxDiff], fmt.Sprintf("… %d líneas más", len(diff)-maxDiff))
		}
	}
	return out, diff
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

func or(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

var verdictText = map[Level]string{OK: "SIN CAMBIOS INESPERADOS", Review: "REVISAR", Regression: "REGRESIÓN"}
var levelText = map[Level]string{Info: "info", Review: "revisar", Regression: "REGRESIÓN"}

func (r Report) Text() string {
	var b strings.Builder
	for _, d := range r.Devices {
		fmt.Fprintf(&b, "%s (%s): %s\n", or(d.Hostname, "?"), d.Address, verdictText[d.Verdict])
		for _, f := range d.Findings {
			fmt.Fprintf(&b, "  %-10s %-10s %s\n", levelText[f.Level], f.Facet, f.Detail)
		}
		for _, l := range d.ConfigDiff {
			b.WriteString("    " + l + "\n")
		}
	}
	b.WriteString(r.Note + "\n")
	return b.String()
}
