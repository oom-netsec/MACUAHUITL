// Package msgkb es la base de conocimiento de mensajes de syslog de Cisco: para cada
// mnemónico (%FAC-SEV-NOMBRE) trae el significado, la causa probable, la acción y los
// comandos de verificación. Los datos salen de la documentación pública de Cisco y están
// sin validar en laboratorio. No toca la red.
package msgkb

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

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
}

// source se pone a todas las entradas: la base no tiene transcripciones de equipos reales.
const source = "documentación pública de Cisco (sin validar en laboratorio)"

// KB es un conjunto de entradas ya validado.
type KB struct{ entries []Entry }

var idRe = regexp.MustCompile(`^%[A-Z0-9_]+(?:-(?:[0-7]|\*)(?:-[A-Z0-9_*]+)?|-\*)$`)

// Load lee un YAML de entradas. Falla si un ID es inválido o está repetido, si falta un
// campo o si un comando de verificación no es de lectura.
func Load(data []byte) (*KB, error) {
	var es []Entry
	if err := yaml.Unmarshal(data, &es); err != nil {
		return nil, fmt.Errorf("msgkb: %w", err)
	}
	seen := map[string]bool{}
	for i := range es {
		e := &es[i]
		if !idRe.MatchString(e.ID) {
			return nil, fmt.Errorf("msgkb: ID inválido %q", e.ID)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("msgkb: ID repetido %s", e.ID)
		}
		seen[e.ID] = true
		if e.Meaning == "" || e.Cause == "" || e.Action == "" || len(e.Verify) == 0 {
			return nil, fmt.Errorf("msgkb: %s: faltan significado, causa, acción o verificación", e.ID)
		}
		for _, c := range e.Verify {
			if err := playbook.CheckDenied("ios", c); err != nil {
				return nil, fmt.Errorf("msgkb: %s: %w", e.ID, err)
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
			defErr = errors.New("msgkb: la base incrustada está vacía")
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
		return nil, fmt.Errorf("msgkb: la consulta excede %d caracteres", MaxQuery)
	}
	for _, r := range q {
		if r < 0x20 || r > 0x7e {
			return nil, errors.New("msgkb: la consulta solo admite ASCII imprimible")
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

var sevNames = [...]string{"emergencia", "alerta", "crítica", "error", "advertencia", "aviso", "informativo", "depuración"}

// Text arma la ficha legible de las entradas (la CLI la imprime tal cual).
func Text(es []Entry) string {
	if len(es) == 0 {
		return "sin coincidencias en la base de mensajes"
	}
	var b strings.Builder
	for i, e := range es {
		if i > 0 {
			b.WriteByte('\n')
		}
		sev := "varía"
		if e.Severity >= 0 && e.Severity < len(sevNames) {
			sev = fmt.Sprintf("%d %s", e.Severity, sevNames[e.Severity])
		}
		fmt.Fprintf(&b, "%s  (severidad %s)\n  Significado: %s\n  Causa probable: %s\n  Acción: %s\n  Verificar (solo lectura):\n", e.ID, sev, e.Meaning, e.Cause, e.Action)
		for _, c := range e.Verify {
			fmt.Fprintf(&b, "    %s\n", c)
		}
		fmt.Fprintf(&b, "  Fuente: %s\n", e.Source)
	}
	return strings.TrimRight(b.String(), "\n")
}
