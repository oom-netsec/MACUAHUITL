// Package cleaner ordena una configuración IOS/IOS-XE para leerla y compararla:
// quita líneas vacías y "!" repetidos, recorta espacios finales, ordena
// opcionalmente bloques independientes y marca las líneas huérfanas.
//
// Nunca borra en silencio: cada eliminación o cambio sale en Result.Changes con su
// línea de origen, y las huérfanas solo se marcan (con un comentario "!"), jamás se quitan.
// Los cuerpos de banner y macro son texto y no se tocan. No hace: red ni leer archivos.
package cleaner

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

const (
	RuleBlank = "linea-vacia"
	RuleBang  = "separador-repetido"
	RuleTrail = "espacio-final"
	RuleSort  = "orden"
)

type Options struct {
	// Sort ordena grupos contiguos de interfaces, VLAN, rutas estáticas y usuarios.
	Sort bool
}

// Change es un cambio hecho al texto; Line es la línea de la entrada original (desde 1).
type Change struct {
	Rule string `json:"rule"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// Orphan es una línea que apunta a algo que no existe (o una definición sin uso).
type Orphan struct {
	Line int    `json:"line"`
	Text string `json:"text"`
	Why  string `json:"why"`
}

type Result struct {
	Output  string   `json:"output"`
	Changes []Change `json:"changes"`
	Orphans []Orphan `json:"orphans"`
}

type line struct {
	no        int
	text      string
	protected bool // cuerpo de banner o macro
	verbatim  bool // apertura de un texto multilínea: el espacio final es parte del texto
	mark      string
}

// bannerRe: textos con delimitador (banner, refuse/vacant-message de line, menu title/prompt/text).
var bannerRe = regexp.MustCompile(`^(?:banner \S+|(?:vacant|refuse)-message|menu \S+ (?:title|prompt|text \S+)) (.+)$`)

func isBang(s string) bool { return strings.TrimSpace(s) == "!" }

// scan numera las líneas y marca las protegidas (banner y macro), con la misma regla que iosconf.
func scan(text string) []line {
	raw := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if raw[len(raw)-1] == "" {
		raw = raw[:len(raw)-1]
	}
	ls := make([]line, len(raw))
	for i, t := range raw {
		ls[i] = line{no: i + 1, text: t}
	}
	for i := 0; i < len(ls); i++ {
		t := strings.TrimSpace(ls[i].text)
		end := ""
		if m := bannerRe.FindStringSubmatch(t); m != nil {
			end = m[1]
			if strings.HasPrefix(end, "^C") {
				end = "^C"
			} else {
				end = string([]rune(end)[0])
			}
			if strings.Contains(strings.TrimPrefix(m[1], end), end) {
				continue // cerrado en la misma línea
			}
		} else if strings.HasPrefix(t, "macro name ") {
			end = "@"
		}
		if end == "" {
			continue
		}
		ls[i].verbatim = true
		for i++; i < len(ls); i++ {
			ls[i].protected = true
			if end == "@" && strings.TrimSpace(ls[i].text) == "@" || end != "@" && strings.Contains(ls[i].text, end) {
				break
			}
		}
	}
	return ls
}

// Clean limpia text. Nunca falla: lo que no reconoce lo deja como está.
func Clean(text string, o Options) Result {
	r := Result{Changes: []Change{}, Orphans: []Orphan{}}
	if strings.TrimSpace(text) == "" {
		r.Output = ""
		return r
	}
	ls := scan(text)
	orph := orphans(text)
	var kept []line
	for _, l := range ls {
		if !l.protected {
			if t := strings.TrimRight(l.text, " \t\r"); t != l.text && !l.verbatim {
				r.Changes = append(r.Changes, Change{RuleTrail, l.no, l.text})
				l.text = t
			}
			switch {
			case l.text == "":
				r.Changes = append(r.Changes, Change{RuleBlank, l.no, ""})
				continue
			case isBang(l.text) && len(kept) > 0 && !kept[len(kept)-1].protected && isBang(kept[len(kept)-1].text):
				r.Changes = append(r.Changes, Change{RuleBang, l.no, "!"})
				continue
			}
		}
		if o, ok := orph[l.no]; ok {
			l.mark = o.Why
			r.Orphans = append(r.Orphans, o)
		}
		kept = append(kept, l)
	}
	if o.Sort {
		kept = sortBlocks(kept, &r)
	}
	var b strings.Builder
	for _, l := range kept {
		if l.mark != "" {
			b.WriteString("! HUERFANA: " + l.mark + "\n")
		}
		b.WriteString(l.text + "\n")
	}
	r.Output = b.String()
	sort.SliceStable(r.Orphans, func(i, j int) bool { return r.Orphans[i].Line < r.Orphans[j].Line })
	return r
}

// ---- Huérfanas ----

var (
	aclDef = regexp.MustCompile(`^(?:ip access-list (?:standard|extended)|ipv6 access-list|access-list) (\S+)`)
	aclRef = regexp.MustCompile(`^(?:(ip access-group|ipv6 traffic-filter) (\S+)|(access-class) (\S+))`)
	rmDef  = regexp.MustCompile(`^route-map (\S+)`)
	rmRef  = regexp.MustCompile(`\broute-map (\S+)`)
	cmDef  = regexp.MustCompile(`^class-map (?:type \S+ )?(?:(?:match-any|match-all) )?(\S+)$`)
	cmRef  = regexp.MustCompile(`^(?:class|match class-map) (\S+)$`)
	pmDef  = regexp.MustCompile(`^policy-map (?:type \S+ )?(\S+)$`)
	pmRef  = regexp.MustCompile(`^service-policy (?:input |output )?(?:type \S+ )?(\S+)$`)
)

// orphans lee la configuración original (sus números de línea son los de la entrada).
func orphans(text string) map[int]Orphan {
	acls, rms, cms, pms := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	used := map[string]bool{}
	type ref struct {
		n         *iosconf.Node
		kind, key string
		via       string
	}
	var refs []ref
	var cmDefs []*iosconf.Node
	root := iosconf.Parse(text)
	root.Walk(func(n *iosconf.Node) {
		top := n.Parent == root
		switch {
		case strings.HasPrefix(n.Line, "no "):
			return
		case top && aclDef.MatchString(n.Line):
			acls[aclDef.FindStringSubmatch(n.Line)[1]] = true
		case top && rmDef.MatchString(n.Line):
			rms[rmDef.FindStringSubmatch(n.Line)[1]] = true
		case top && cmDef.MatchString(n.Line):
			cms[cmDef.FindStringSubmatch(n.Line)[1]] = true
			cmDefs = append(cmDefs, n)
		case top && pmDef.MatchString(n.Line):
			pms[pmDef.FindStringSubmatch(n.Line)[1]] = true
		}
		if m := aclRef.FindStringSubmatch(n.Line); m != nil {
			via, key := m[1], m[2]
			if m[3] != "" {
				via, key = m[3], m[4]
			}
			refs = append(refs, ref{n, "ACL", key, via})
		}
		if m := rmRef.FindStringSubmatch(n.Line); m != nil {
			refs = append(refs, ref{n, "route-map", m[1], "route-map"})
		}
		if m := cmRef.FindStringSubmatch(n.Line); m != nil && m[1] != "class-default" && (strings.HasPrefix(n.Line, "match ") || strings.HasPrefix(n.Parent.Line, "policy-map ") || strings.HasPrefix(n.Parent.Line, "class-map ")) {
			refs = append(refs, ref{n, "class-map", m[1], "class"})
			used[m[1]] = true
		}
		if m := pmRef.FindStringSubmatch(n.Line); m != nil {
			refs = append(refs, ref{n, "policy-map", m[1], "service-policy"})
		}
	})
	defined := map[string]map[string]bool{"ACL": acls, "route-map": rms, "class-map": cms, "policy-map": pms}
	out := map[int]Orphan{}
	for _, r := range refs {
		if !defined[r.kind][r.key] {
			why := fmt.Sprintf("%s %s no existe (%s)", r.kind, r.key, r.via)
			out[r.n.Num] = Orphan{r.n.Num, r.n.Line, why}
		}
	}
	for _, n := range cmDefs {
		if k := cmDef.FindStringSubmatch(n.Line)[1]; !used[k] {
			out[n.Num] = Orphan{n.Num, n.Line, fmt.Sprintf("class-map %s sin uso (ningún policy-map la usa)", k)}
		}
	}
	return out
}

// ---- Orden opcional ----

var sortable = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"interface", regexp.MustCompile(`^interface \S+`)},
	{"vlan", regexp.MustCompile(`^vlan \d+$`)},
	{"ip route", regexp.MustCompile(`^ip route `)},
	{"username", regexp.MustCompile(`^username `)},
}

type chunk struct {
	lines []line
	kind  string
}

func kindOf(l line) string {
	for _, s := range sortable {
		if s.re.MatchString(l.text) {
			return s.kind
		}
	}
	return ""
}

// sortBlocks ordena, en orden natural, cada grupo contiguo de bloques del mismo tipo.
// Un bloque es su línea de primer nivel con todo lo que le sigue hasta la próxima.
func sortBlocks(ls []line, r *Result) []line {
	var chunks []chunk
	for _, l := range ls {
		top := !l.protected && l.text != "" && !strings.HasPrefix(l.text, " ") && !strings.HasPrefix(l.text, "!")
		if top || len(chunks) == 0 {
			chunks = append(chunks, chunk{kind: kindOf(l)})
		}
		c := &chunks[len(chunks)-1]
		c.lines = append(c.lines, l)
	}
	var out []line
	for i := 0; i < len(chunks); {
		j := i + 1
		for chunks[i].kind != "" && j < len(chunks) && chunks[j].kind == chunks[i].kind {
			j++
		}
		run := append([]chunk(nil), chunks[i:j]...)
		if j-i > 1 {
			sort.SliceStable(run, func(a, b int) bool { return natLess(run[a].lines[0].text, run[b].lines[0].text) })
			for k := range run {
				if run[k].lines[0].no != chunks[i+k].lines[0].no {
					r.Changes = append(r.Changes, Change{RuleSort, chunks[i].lines[0].no, fmt.Sprintf("%d bloques %q reordenados", j-i, chunks[i].kind)})
					break
				}
			}
		}
		for _, c := range run {
			out = append(out, c.lines...)
		}
		i = j
	}
	return out
}

// natLess compara con los números como números ("Gi1/0/2" antes de "Gi1/0/10").
func natLess(a, b string) bool {
	for a != "" && b != "" {
		ta, tb := token(a), token(b)
		a, b = a[len(ta):], b[len(tb):]
		if ta == tb {
			continue
		}
		na, ea := strconv.Atoi(ta)
		nb, eb := strconv.Atoi(tb)
		if ea == nil && eb == nil && na != nb {
			return na < nb
		}
		return ta < tb
	}
	return len(a) < len(b)
}

func token(s string) string {
	d := unicode.IsDigit(rune(s[0]))
	for i, c := range s {
		if unicode.IsDigit(c) != d {
			return s[:i]
		}
	}
	return s
}

// ---- Reporte ----

func ranges(ns []int) string {
	var parts []string
	for i := 0; i < len(ns); {
		j := i
		for j+1 < len(ns) && ns[j+1] == ns[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", ns[i], ns[j]))
		} else {
			parts = append(parts, strconv.Itoa(ns[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ", ")
}

func (r Result) Text() string {
	var b strings.Builder
	for _, g := range []struct{ rule, label string }{{RuleBlank, "líneas vacías quitadas"}, {RuleBang, "separadores ! repetidos quitados"}, {RuleTrail, "líneas con espacio final recortado"}} {
		var ns []int
		for _, c := range r.Changes {
			if c.Rule == g.rule {
				ns = append(ns, c.Line)
			}
		}
		if len(ns) > 0 {
			fmt.Fprintf(&b, "%d %s (líneas de origen: %s)\n", len(ns), g.label, ranges(ns))
		}
	}
	for _, c := range r.Changes {
		if c.Rule == RuleSort {
			fmt.Fprintf(&b, "orden: %s (desde la línea %d)\n", c.Text, c.Line)
		}
	}
	if len(r.Changes) == 0 {
		b.WriteString("Sin cambios de formato.\n")
	}
	if len(r.Orphans) > 0 {
		fmt.Fprintf(&b, "\n%d HUÉRFANAS (marcadas con un comentario ! en la salida)\n", len(r.Orphans))
		for _, o := range r.Orphans {
			fmt.Fprintf(&b, "  línea %d: %s — %s\n", o.Line, o.Text, o.Why)
		}
		b.WriteString("Las huérfanas solo se marcan: la limpieza nunca las quita.\n")
	}
	return b.String()
}
