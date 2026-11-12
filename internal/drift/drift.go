// Package drift compara el running-config de dos rondas de un equipo y dice qué
// líneas entraron y cuáles salieron, sin el ruido que cambia solo en cada ronda.
//
// shortcut: compara por línea con su sección; un cambio de orden de líneas que importan
// (una ACL sin secuencia) no se reporta. Subir a un diff con orden si hace falta.
// No hace: red ni leer archivos; el servicio le entrega los textos.
package drift

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

// volatile: líneas que cambian solas entre rondas y no son deriva.
var volatile = regexp.MustCompile(`(?i)^(ntp clock-period\b|! ?Last configuration change\b|! ?NVRAM config last updated\b|Current configuration\s*:)`)

// Change es una línea que entró (+) o salió (-). Path es su sección ("interface Gi1/0/1"), vacío en el nivel superior.
type Change struct {
	Op   string `json:"op"`
	Path string `json:"path"`
	Line string `json:"line"`
}

type entry struct{ path, line string }

// split separa las líneas volátiles del resto del texto.
func split(text string) (clean string, vol []string) {
	var b strings.Builder
	for _, ln := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		if t := strings.TrimSpace(ln); volatile.MatchString(t) {
			vol = append(vol, t)
			continue
		}
		b.WriteString(ln + "\n")
	}
	return b.String(), vol
}

func flatten(text string) []entry {
	var out []entry
	iosconf.Parse(text).Walk(func(n *iosconf.Node) {
		l := n.Line
		if n.Body != "" {
			l += "\n" + n.Body
		}
		out = append(out, entry{n.Parent.Path(), l})
	})
	return out
}

func counts(es []entry) map[entry]int {
	m := map[entry]int{}
	for _, e := range es {
		m[e]++
	}
	return m
}

// without devuelve las entradas de a que no están en b, respetando repeticiones.
func without(a []entry, b map[entry]int) []entry {
	var out []entry
	for _, e := range a {
		if b[e] > 0 {
			b[e]--
		} else {
			out = append(out, e)
		}
	}
	return out
}

// Compare devuelve primero lo que salió y luego lo que entró, en el orden de cada configuración,
// y las líneas volátiles que difirieron entre las dos rondas (ignoradas, pero visibles).
func Compare(prev, cur string) (changes []Change, ignored []string) {
	pc, pv := split(prev)
	cc, cv := split(cur)
	a, b := flatten(pc), flatten(cc)
	for _, e := range without(a, counts(b)) {
		changes = append(changes, Change{"-", e.path, e.line})
	}
	for _, e := range without(b, counts(a)) {
		changes = append(changes, Change{"+", e.path, e.line})
	}
	seen := map[string]bool{}
	for _, l := range pv {
		seen[l] = true
	}
	for _, l := range cv {
		if seen[l] {
			delete(seen, l)
		} else {
			ignored = append(ignored, l)
		}
	}
	for _, l := range pv {
		if seen[l] {
			ignored = append(ignored, l)
			delete(seen, l)
		}
	}
	return changes, ignored
}

type DeviceDrift struct {
	Device  string   `json:"device"`
	From    int      `json:"from"`
	To      int      `json:"to"`
	Added   int      `json:"added"`
	Removed int      `json:"removed"`
	Changes []Change `json:"changes"`
	Ignored []string `json:"ignored"`
}

// NewDevice arma el resultado de un equipo con sus conteos.
func NewDevice(device string, from, to int, cs []Change, ignored []string) DeviceDrift {
	d := DeviceDrift{Device: device, From: from, To: to, Changes: cs, Ignored: ignored}
	if d.Changes == nil {
		d.Changes = []Change{}
	}
	if d.Ignored == nil {
		d.Ignored = []string{}
	}
	for _, c := range cs {
		if c.Op == "+" {
			d.Added++
		} else {
			d.Removed++
		}
	}
	return d
}

type Report struct {
	Dir      string        `json:"dir"`
	From     int           `json:"from"` // pedidas; cada equipo trae las suyas
	To       int           `json:"to"`
	Devices  []DeviceDrift `json:"devices"`
	Warnings []string      `json:"warnings"`
	// WarningsTx son los avisos como texto (mismo largo y orden); no viajan en el JSON.
	WarningsTx []i18n.Text `json:"-"`
	// Masked: el trabajo enmascaró secretos, así que un cambio de enable secret, snmp community o key-string no se ve.
	Masked bool `json:"masked"`
}

// MaskedNotice es el aviso (en español) que acompaña al informe cuando Masked es verdadero. Su texto vive en el
// catálogo (drift.masked_notice), la única fuente: el respaldo y la deriva leen de ahí.
var MaskedNotice = i18n.Msg(i18n.Es, "drift.masked_notice", nil)

// Text es el informe legible, en español.
func (r Report) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el informe en el idioma pedido (con es, el de siempre); los avisos ya vienen en ese idioma si el
// informe pasó por i18n.Localize.
func (r Report) TextIn(loc string) string {
	var b strings.Builder
	m := func(key string, kv ...any) string { return i18n.Msg(loc, key, i18n.A(kv...)) }
	n := 0
	if r.Masked {
		fmt.Fprintf(&b, "%s\n\n", m("drift.text.warning", "message", m("drift.masked_notice")))
	}
	for _, d := range r.Devices {
		if len(d.Changes) == 0 {
			fmt.Fprintf(&b, "%s\n", m("drift.text.none", "device", d.Device, "to", d.To, "from", d.From))
		} else {
			n++
			fmt.Fprintf(&b, "%s\n", m("drift.text.changes", "device", d.Device, "n", len(d.Changes), "added", d.Added, "removed", d.Removed, "to", d.To, "from", d.From))
			last := "\x00"
			for _, c := range d.Changes {
				if c.Path != last {
					if c.Path != "" {
						fmt.Fprintf(&b, "  %s\n", c.Path)
					}
					last = c.Path
				}
				fmt.Fprintf(&b, "    %s %s\n", c.Op, strings.ReplaceAll(c.Line, "\n", "\n      "))
			}
		}
		if len(d.Ignored) > 0 {
			fmt.Fprintf(&b, "  %s\n", m("drift.text.ignored", "list", strings.Join(d.Ignored, "; ")))
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "%s\n", m("drift.text.warn", "message", w))
	}
	fmt.Fprintf(&b, "\n%s\n", m("drift.text.total", "n", n, "total", len(r.Devices)))
	return b.String()
}

// IsRunningConfig dice si un comando de Patrol es el running-config completo (no un filtrado).
// IOS acepta prefijos únicos: "sh run", "show running", "sh ru". Solo sin argumentos: "all", "full"
// y cualquier "| filtro" dan otro texto y no se comparan con el completo.
func IsRunningConfig(cmd string) bool {
	f := strings.Fields(strings.ToLower(cmd))
	return len(f) == 2 && prefix(f[0], "show", 2) && prefix(f[1], "running-config", 2)
}

// prefix: s es un prefijo de full de al menos min letras.
func prefix(s, full string, min int) bool { return len(s) >= min && strings.HasPrefix(full, s) }

// Pair elige las dos rondas a comparar entre las que tienen configuración: to (0 = la última)
// y la que la precede. Si la ronda pedida no está, o no hay una anterior, devuelve ok=false.
func Pair(have []int, to int) (from, toRound int, ok bool) {
	has := map[int]bool{}
	for _, r := range have {
		has[r] = true
		if to == 0 && r > toRound {
			toRound = r
		}
	}
	if to != 0 {
		toRound = to
	}
	if !has[toRound] {
		return 0, 0, false
	}
	for r := range has {
		if r < toRound && r > from {
			from = r
		}
	}
	return from, toRound, from != 0
}
