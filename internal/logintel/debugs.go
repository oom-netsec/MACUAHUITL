package logintel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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

	ReasonT []i18n.Text `json:"-"` // los motivos (unidos con «; » en Reason) como texto de catálogo
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
	WarnT       []i18n.Text    `json:"-"` // los Warnings como texto de catálogo, en paralelo
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
		var whyT []i18n.Text
		if g.Count <= o.RareMax && famCount[g.family] >= o.FamilyMin {
			whyT = append(whyT, i18n.Tx("logintel.debug.rare", "n", famCount[g.family], "family", g.family))
			why = append(why, whyT[len(whyT)-1].In(i18n.Es))
		}
		if alarmRe.MatchString(g.raw) {
			whyT = append(whyT, i18n.Tx("logintel.debug.alarm"))
			why = append(why, whyT[len(whyT)-1].In(i18n.Es))
		}
		if len(why) == 0 {
			continue
		}
		if len(rep.Anomalies) == MaxAnomalies {
			skipped++
			continue
		}
		rep.Anomalies = append(rep.Anomalies, DebugAnomaly{Line: g.line, Text: g.raw, Reason: strings.Join(why, "; "), Family: g.family, FamilyCount: famCount[g.family], ReasonT: whyT})
	}
	if skipped > 0 {
		i18n.Note(&rep.Warnings, &rep.WarnT, "logintel.debug.more", "n", skipped, "max", MaxAnomalies)
	}
	if overflow > 0 {
		i18n.Note(&rep.Warnings, &rep.WarnT, "logintel.debug.overflow", "max", maxPatterns, "n", overflow)
	}
	if rep.Truncated {
		i18n.Note(&rep.Warnings, &rep.WarnT, "logintel.warn.max_lines", "max", MaxLines)
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

// Localize da el informe con los motivos de las anomalías y los avisos en el idioma dado (con es, tal cual).
func (r DebugReport) Localize(loc string) DebugReport {
	if loc != i18n.En {
		return r
	}
	r.Warnings = i18n.Notes(loc, r.Warnings, r.WarnT)
	r.Anomalies = append([]DebugAnomaly(nil), r.Anomalies...)
	for i, a := range r.Anomalies {
		if len(a.ReasonT) == 0 {
			continue
		}
		parts := make([]string, len(a.ReasonT))
		for j, t := range a.ReasonT {
			parts[j] = t.In(loc)
		}
		r.Anomalies[i].Reason = strings.Join(parts, "; ")
	}
	return r
}

// Text arma el informe legible en español.
func (r DebugReport) Text() string { return r.TextIn(i18n.Es) }

// TextIn arma el informe legible en el idioma dado (r ya viene en ese idioma: ver Localize).
func (r DebugReport) TextIn(loc string) string {
	var b strings.Builder
	m := func(k string, kv ...any) string { return i18n.Msg(loc, k, i18n.A(kv...)) }
	b.WriteString(m("logintel.debug.head", "lines", r.Lines, "hidden", r.Hidden, "blank", r.Blank, "groups", r.GroupsTotal) + "\n")
	if len(r.Noise) > 0 {
		b.WriteString(m("logintel.debug.noise", "noise", strings.Join(r.Noise, ", ")) + "\n")
	}
	b.WriteString("\n" + m("logintel.debug.top") + "\n")
	for _, g := range r.Groups {
		fmt.Fprintf(&b, "  x%d  %s\n", g.Count, g.Pattern)
	}
	b.WriteString("\n" + m("logintel.debug.anomalies") + "\n")
	if len(r.Anomalies) == 0 {
		b.WriteString(m("logintel.debug.no_anomaly") + "\n")
	}
	for _, a := range r.Anomalies {
		b.WriteString(m("logintel.debug.anomaly_row", "line", a.Line, "reason", a.Reason, "text", a.Text) + "\n")
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\n%s: %s\n", m("forensic.label.warning"), w)
	}
	return strings.TrimRight(b.String(), "\n")
}
