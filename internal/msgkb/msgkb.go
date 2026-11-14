// Package msgkb es la base de conocimiento de mensajes de syslog de Cisco: para cada
// mnemónico (%FAC-SEV-NOMBRE) trae el significado, la causa probable, la acción y los
// comandos de verificación. Los datos salen de la documentación pública de Cisco y están
// sin validar en laboratorio. No toca la red.
package msgkb

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

//go:embed kb/*.yaml
var kbFS embed.FS

// MaxQuery acota la consulta de un usuario (o de una línea de log hostil).
const MaxQuery = 128

// Entry es un mensaje conocido. ID puede llevar comodines (%ILPOWER-*): cubre toda la familia.
type Entry struct {
	ID       string   `yaml:"id" json:"id"`
	Severity int      `yaml:"-" json:"severity"` // 0-7; -1 si el ID lo deja abierto
	Meaning  string   `yaml:"meaning" json:"meaning"`
	Cause    string   `yaml:"cause" json:"cause"`
	Action   string   `yaml:"action" json:"action"`
	Verify   []string `yaml:"verify" json:"verify"` // solo lectura: validados con playbook.CheckDenied
	Source   string   `json:"source"`

	// La versión en inglés del texto (en el YAML: meaning_en, cause_en, action_en); no viaja en el JSON.
	MeaningEN string `yaml:"meaning_en" json:"-"`
	CauseEN   string `yaml:"cause_en" json:"-"`
	ActionEN  string `yaml:"action_en" json:"-"`
}

// In da la ficha en el idioma dado: con en, el texto en inglés y la fuente traducida; con es, la ficha tal cual.
func (e Entry) In(loc string) Entry {
	if loc != i18n.En {
		return e
	}
	for _, p := range [][2]*string{{&e.Meaning, &e.MeaningEN}, {&e.Cause, &e.CauseEN}, {&e.Action, &e.ActionEN}} {
		if *p[1] != "" { // sin versión en inglés (un YAML ajeno), queda el español
			*p[0] = *p[1]
		}
	}
	e.Source = i18n.Msg(loc, "msgkb.source", nil)
	return e
}

// EntriesIn da las fichas en el idioma dado (con es, la misma lista).
func EntriesIn(loc string, es []Entry) []Entry {
	if loc != i18n.En {
		return es
	}
	out := make([]Entry, len(es))
	for i, e := range es {
		out[i] = e.In(loc)
	}
	return out
}

// source se pone a todas las entradas: la base no tiene transcripciones de equipos reales.
var source = i18n.Msg(i18n.Es, "msgkb.source", nil)

// KB es un conjunto de entradas ya validado.
type KB struct{ entries []Entry }

var idRe = regexp.MustCompile(`^%[A-Z0-9_]+(?:-(?:[0-7]|\*)(?:-[A-Z0-9_*]+)?|-\*)$`)

// Load lee un YAML de entradas. Falla si un ID es inválido o está repetido, si falta un
// campo o si un comando de verificación no es de lectura.
func Load(data []byte) (*KB, error) {
	var es []Entry
	if err := yaml.Unmarshal(data, &es); err != nil {
		return nil, i18n.Wrap("msgkb.err.yaml", err, nil)
	}
	seen := map[string]bool{}
	for i := range es {
		e := &es[i]
		if !idRe.MatchString(e.ID) {
			return nil, i18n.New("msgkb.err.bad_id", i18n.A("id", e.ID))
		}
		if seen[e.ID] {
			return nil, i18n.New("msgkb.err.dup_id", i18n.A("id", e.ID))
		}
		seen[e.ID] = true
		if e.Meaning == "" || e.Cause == "" || e.Action == "" || len(e.Verify) == 0 {
			return nil, i18n.New("msgkb.err.fields", i18n.A("id", e.ID))
		}
		for _, c := range e.Verify {
			if err := playbook.CheckDenied("ios", c); err != nil {
				return nil, i18n.Wrap("msgkb.err.verify", err, i18n.A("id", e.ID))
			}
		}
		e.Severity, e.Source = -1, source
		if parts := strings.Split(e.ID, "-"); len(parts) >= 2 && len(parts[1]) == 1 && parts[1] != "*" {
			e.Severity = int(parts[1][0] - '0')
		}
	}
	sort.Slice(es, func(i, j int) bool { return es[i].ID < es[j].ID })
	return &KB{entries: es}, nil
}

var (
	defOnce sync.Once
	defKB   *KB
	defErr  error
)

// Default carga la base incrustada (una vez).
func Default() (*KB, error) {
	defOnce.Do(func() {
		var all []byte
		names, err := fs.Glob(kbFS, "kb/*.yaml")
		if err != nil || len(names) == 0 {
			defErr = i18n.New("msgkb.err.empty_kb", nil)
			return
		}
		sort.Strings(names)
		for _, n := range names {
			b, _ := kbFS.ReadFile(n)
			all = append(append(all, b...), '\n')
		}
		defKB, defErr = Load(all)
	})
	return defKB, defErr
}

// normID lleva una consulta a la forma de la base: mayúsculas, con % y sin ":" final.
func normID(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	s = strings.TrimRight(s, ":")
	if s != "" && s[0] != '%' {
		s = "%" + s
	}
	return s
}

// Lookup busca el mnemónico exacto y, si no está, la entrada de comodín más específica
// (la de prefijo literal más largo) que lo cubre.
func (k *KB) Lookup(id string) (Entry, bool) {
	id = normID(id)
	var best *Entry
	for i := range k.entries {
		e := &k.entries[i]
		switch {
		case e.ID == id:
			return *e, true
		case strings.ContainsAny(e.ID, "*?") && glob(e.ID, id):
			if best == nil || len(strings.SplitN(e.ID, "*", 2)[0]) > len(strings.SplitN(best.ID, "*", 2)[0]) {
				best = e
			}
		}
	}
	if best == nil {
		return Entry{}, false
	}
	return *best, true
}

// Search devuelve las entradas cuyo ID coincide con el patrón (* y ? como comodines). Vacío = todas.
func (k *KB) Search(pattern string) []Entry {
	pattern = normID(pattern)
	var out []Entry
	for _, e := range k.entries {
		if pattern == "" || glob(pattern, e.ID) {
			out = append(out, e)
		}
	}
	return out
}

// Query resuelve lo que escribe el usuario: sin comodines, el mnemónico exacto (o su familia);
// con comodines, la búsqueda. Rechaza consultas largas o con caracteres de control.
func (k *KB) Query(q string) ([]Entry, error) {
	if len(q) > MaxQuery {
		return nil, i18n.New("msgkb.err.long", i18n.A("max", MaxQuery))
	}
	for _, r := range q {
		if r < 0x20 || r > 0x7e {
			return nil, i18n.New("msgkb.err.ascii", nil)
		}
	}
	if strings.ContainsAny(q, "*?") || strings.TrimSpace(q) == "" {
		return k.Search(q), nil
	}
	if e, ok := k.Lookup(q); ok {
		return []Entry{e}, nil
	}
	return nil, nil
}

var mnemonicRe = regexp.MustCompile(`%[A-Z0-9_]+-[0-7]-[A-Z0-9_]+`)

// Mnemonic extrae el primer %FAC-SEV-NOMBRE de una línea de log ("" si no hay).
func Mnemonic(line string) string {
	if len(line) > 2048 {
		line = line[:2048]
	}
	return mnemonicRe.FindString(line)
}

// ForLine devuelve la entrada del mnemónico de la línea.
func (k *KB) ForLine(line string) (Entry, bool) {
	m := Mnemonic(line)
	if m == "" {
		return Entry{}, false
	}
	return k.Lookup(m)
}

// glob compara con * (cualquier tramo) y ? (un carácter). Retrocede solo al último *,
// así que el costo es O(len(pat)*len(s)) en el peor caso, sin regex.
func glob(pat, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pat) && (pat[p] == '?' || pat[p] == s[i]) && pat[p] != '*':
			p++
			i++
		case p < len(pat) && pat[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p, mark = star+1, mark+1
			i = mark
		default:
			return false
		}
	}
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
}

// Text arma la ficha legible de las entradas en español (la CLI la imprime tal cual).
func Text(es []Entry) string { return TextIn(i18n.Es, es) }

// TextIn arma la ficha legible en el idioma dado; las entradas ya vienen en ese idioma (ver EntriesIn).
func TextIn(loc string, es []Entry) string {
	if len(es) == 0 {
		return i18n.Msg(loc, "msgkb.none", nil)
	}
	var b strings.Builder
	for i, e := range es {
		if i > 0 {
			b.WriteByte('\n')
		}
		sev := i18n.Msg(loc, "msgkb.varies", nil)
		if e.Severity >= 0 && e.Severity < 8 {
			sev = fmt.Sprintf("%d %s", e.Severity, i18n.Msg(loc, fmt.Sprintf("msgkb.sev.%d", e.Severity), nil))
		}
		b.WriteString(i18n.Msg(loc, "msgkb.text.head", i18n.A("id", e.ID, "severity", sev)) + "\n")
		b.WriteString(i18n.Msg(loc, "msgkb.text.meaning", i18n.A("v", e.Meaning)) + "\n")
		b.WriteString(i18n.Msg(loc, "msgkb.text.cause", i18n.A("v", e.Cause)) + "\n")
		b.WriteString(i18n.Msg(loc, "msgkb.text.action", i18n.A("v", e.Action)) + "\n")
		b.WriteString(i18n.Msg(loc, "msgkb.text.verify", nil) + "\n")
		for _, c := range e.Verify {
			fmt.Fprintf(&b, "    %s\n", c)
		}
		b.WriteString(i18n.Msg(loc, "msgkb.text.source", i18n.A("v", e.Source)) + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}
