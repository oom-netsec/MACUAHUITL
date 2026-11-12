package logintel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

const (
	MaxAnomalies = 100
	MaxNoise     = 50
	MaxNoiseLen  = 128
	maxPatterns  = 5000
	defaultTop   = 50
)

// DebugOptions: Noise son textos que se ocultan (sin distinguir mayúsculas); una línea es rara si su
// patrón aparece RareMax veces o menos dentro de una familia de FamilyMin líneas o más.
type DebugOptions struct {
	Noise     []string
	FamilyMin int
	RareMax   int
	Top       int
}

// DebugGroup es un patrón de línea repetido.
type DebugGroup struct {
	Pattern string `json:"pattern"`
	Count   int    `json:"count"`
	Example string `json:"example"`
}

// DebugAnomaly es un patrón raro o con palabra de alarma, con la primera línea donde aparece.
type DebugAnomaly struct {
	Line        int    `json:"line"`
	Text        string `json:"text"`
	Reason      string `json:"reason"`
	Family      string `json:"family"`
	FamilyCount int    `json:"family_count"`
}

type DebugReport struct {
	Lines       int            `json:"lines"`
	Blank       int            `json:"blank"`
	Hidden      int            `json:"hidden"`
	Noise       []string       `json:"noise"`
	GroupsTotal int            `json:"groups_total"`
	Groups      []DebugGroup   `json:"groups"`
	Anomalies   []DebugAnomaly `json:"anomalies"`
	Truncated   bool           `json:"truncated,omitempty"`
	Warnings    []string       `json:"warnings,omitempty"`
}

var alarmRe = regexp.MustCompile(`(?i)\b(error|errors|fail|failed|failure|invalid|mismatch(?:ed)?|time(?:d )?out|unexpected|denied|reject(?:ed)?|drop(?:ped)?|discard(?:ed)?|bad|illegal|unknown|dead|lost|retransmi\w*|loop\w*|exceed(?:ed)?|overflow|crash\w*|abort\w*)\b`)

type dgroup struct {
	DebugGroup
	line   int
	family string
	raw    string
}

// FilterDebug agrupa las líneas repetidas de un debug (normalizadas, sin la marca de hora), oculta el
// ruido y marca las anomalías. Trabaja solo sobre texto: nunca se conecta a un equipo.
func FilterDebug(text string, o DebugOptions) DebugReport {
	if o.FamilyMin <= 0 {
		o.FamilyMin = 20
	}
	if o.RareMax <= 0 {
		o.RareMax = 2
	}
	if o.Top <= 0 || o.Top > defaultTop*10 {
		o.Top = defaultTop
	}
	rep := DebugReport{Noise: []string{}, Groups: []DebugGroup{}, Anomalies: []DebugAnomaly{}}
	for _, n := range o.Noise {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || len(rep.Noise) == MaxNoise {
			continue
		}
		if len(n) > MaxNoiseLen {
			n = n[:MaxNoiseLen]
		}
		rep.Noise = append(rep.Noise, n)
	}
	groups := map[string]*dgroup{}
	famCount := map[string]int{}
	overflow := 0
	for len(text) > 0 {
		var ln string
		if i := strings.IndexByte(text, '\n'); i >= 0 {
			ln, text = text[:i], text[i+1:]
		} else {
			ln, text = text, ""
		}
		if rep.Lines == MaxLines {
			rep.Truncated = true
			break
		}
		rep.Lines++
		if len(ln) > MaxLine {
			ln = ln[:MaxLine]
		}
		ln = strings.TrimSpace(strings.ToValidUTF8(ln, "?"))
		if ln == "" {
			rep.Blank++
			continue
		}
		body := ln
		if l, ok := iosxe.ParseLogLine(ln); ok {
			body = strings.TrimSpace(l.Text)
		}
		low := strings.ToLower(body)
		hidden := false
		for _, n := range rep.Noise {
			if strings.Contains(low, n) {
				hidden = true
				break
			}
		}
		if hidden {
			rep.Hidden++
			continue
		}
		pat := Normalize(body)
		g := groups[pat]
		if g == nil {
			if len(groups) >= maxPatterns {
				overflow++
				continue
			}
			g = &dgroup{DebugGroup: DebugGroup{Pattern: pat, Example: body}, line: rep.Lines, family: family(pat), raw: body}
			groups[pat] = g
		}
		g.Count++
		famCount[g.family]++
	}
	var all []*dgroup
	for _, g := range groups {
		all = append(all, g)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Count != all[j].Count {
			return all[i].Count > all[j].Count
		}
		return all[i].Pattern < all[j].Pattern
	})
	rep.GroupsTotal = len(all)
	for i, g := range all {
		if i < o.Top {
			rep.Groups = append(rep.Groups, g.DebugGroup)
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].line < all[j].line })
	skipped := 0
	for _, g := range all {
		var why []string
		if g.Count <= o.RareMax && famCount[g.family] >= o.FamilyMin {
			why = append(why, fmt.Sprintf("rara dentro de una familia frecuente (%d línea(s) de «%s»)", famCount[g.family], g.family))
		}
		if alarmRe.MatchString(g.raw) {
			why = append(why, "contiene una palabra de alarma")
		}
		if len(why) == 0 {
			continue
		}
		if len(rep.Anomalies) == MaxAnomalies {
			skipped++
			continue
		}
		rep.Anomalies = append(rep.Anomalies, DebugAnomaly{Line: g.line, Text: g.raw, Reason: strings.Join(why, "; "), Family: g.family, FamilyCount: famCount[g.family]})
	}
	if skipped > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("hay %d anomalía(s) más; solo se muestran las primeras %d", skipped, MaxAnomalies))
	}
	if overflow > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("hay más de %d patrones: %d línea(s) de patrones nuevos no se agruparon", maxPatterns, overflow))
	}
	if rep.Truncated {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("se leyeron solo las primeras %d líneas", MaxLines))
	}
	return rep
}

// family es la clave que agrupa patrones del mismo tipo de línea: la primera palabra normalizada
// ("OSPF-<n>", "IP:", "RIP:"). Es simple a propósito: una segunda palabra separaría "RIP: sending"
// de "RIP: peer" y ninguna rareza quedaría dentro de una familia frecuente.
func family(pat string) string {
	f := strings.Fields(pat)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// Text arma el informe legible.
func (r DebugReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d línea(s): %d líneas ocultas por ruido, %d en blanco, %d patrón(es).\n", r.Lines, r.Hidden, r.Blank, r.GroupsTotal)
	if len(r.Noise) > 0 {
		fmt.Fprintf(&b, "Ruido oculto: %s\n", strings.Join(r.Noise, ", "))
	}
	b.WriteString("\nPatrones más frecuentes:\n")
	for _, g := range r.Groups {
		fmt.Fprintf(&b, "  x%d  %s\n", g.Count, g.Pattern)
	}
	b.WriteString("\nAnomalías:\n")
	if len(r.Anomalies) == 0 {
		b.WriteString("  ninguna\n")
	}
	for _, a := range r.Anomalies {
		fmt.Fprintf(&b, "  línea %d [%s]: %s\n", a.Line, a.Reason, a.Text)
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\nAviso: %s\n", w)
	}
	return strings.TrimRight(b.String(), "\n")
}
