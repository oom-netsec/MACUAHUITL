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
	"github.com/oom-netsec/MACUAHUITL/internal/mask"
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

// TextIn es el cambio como se imprime: «+ línea», «- línea» o, si solo cambió el secreto, «~ línea (la clave cambió)».
func (c Change) TextIn(loc string) string {
	s := c.Op + " " + strings.ReplaceAll(c.Line, "\n", "\n      ")
	if c.Op == "~" {
		s += " " + i18n.Msg(loc, "drift.secret_changed", nil)
	}
	return s
}

// CompareMasked es Compare para mostrar: enmascara los dos lados con las mismas reglas, así ningún secreto ni hash
// (tipo 5/7, que se rompen) sale en el informe y un lado ya enmascarado no da diferencias falsas. Si los dos traían el
// valor real y una línea solo cambió en un valor que se enmascara (una clave; en ASA sin plataforma, también la IP de
// snmp-server host), sale una vez con Op "~", enmascarada en su contexto: el informe dice que cambió sin mostrarlo.
// Límite: una cadena de certificados se enmascara entera en los dos lados, así que renovar un certificado (que es
// público) no se ve en el informe; para eso está ver el respaldo.
func CompareMasked(prev, cur, platform string) (changes []Change, ignored []string) {
	mp, _ := mask.Apply(platform, prev)
	mc, _ := mask.Apply(platform, cur)
	changes, ignored = Compare(mp, mc)
	raw, _ := Compare(prev, cur)
	type key struct{ path, line string }
	removed := map[key]int{}
	for _, c := range raw {
		if c.Op == "-" && !strings.Contains(c.Line, "<MASKED:") { // un lado ya enmascarado no sabe si la clave cambió
			if path, line, ok := maskInContext(platform, c.Path, c.Line); ok {
				removed[key{path, line}]++
			}
		}
	}
	for _, c := range raw {
		if c.Op != "+" || strings.Contains(c.Line, "<MASKED:") {
			continue
		}
		path, line, ok := maskInContext(platform, c.Path, c.Line)
		if k := (key{path, line}); ok && removed[k] > 0 { // misma línea enmascarada que salió: solo cambió el secreto
			removed[k]--
			changes = append(changes, Change{"~", path, line})
		}
	}
	return changes, ignored
}

// maskInContext enmascara una línea con sus secciones delante (una regla puede depender del bloque, como el password
// de line vty) y devuelve la ruta y la línea ya enmascaradas.
func maskInContext(platform, path, line string) (string, string, bool) {
	var segs []string
	if path != "" {
		segs = strings.Split(path, " > ")
	}
	var b strings.Builder
	for i, seg := range segs {
		b.WriteString(strings.Repeat(" ", i) + seg + "\n")
	}
	ind := strings.Repeat(" ", len(segs))
	for _, l := range strings.Split(line, "\n") {
		b.WriteString(ind + l + "\n")
	}
	out, _ := mask.Apply(platform, b.String())
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != len(segs)+strings.Count(line, "\n")+1 { // el enmascarado quitó o juntó líneas (cadena de certificados): no se alinea
		return "", "", false
	}
	for i := range segs {
		segs[i] = strings.TrimPrefix(lines[i], strings.Repeat(" ", i))
	}
	body := lines[len(segs):]
	for i := range body {
		body[i] = strings.TrimPrefix(body[i], ind)
	}
	return strings.Join(segs, " > "), strings.Join(body, "\n"), true
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
		switch c.Op {
		case "+":
			d.Added++
		case "-":
			d.Removed++
		} // «~»: cambió un valor enmascarado; no es ni agregada ni quitada
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
				fmt.Fprintf(&b, "    %s\n", c.TextIn(loc))
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
