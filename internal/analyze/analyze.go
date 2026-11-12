package analyze

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Finding es un hallazgo: la regla, dónde y cuándo se vio, y las líneas exactas que lo sustentan.
type Finding struct {
	Rule        string    `json:"rule"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Device      string    `json:"device"`
	Round       int       `json:"round"`
	At          time.Time `json:"at"`
	Command     string    `json:"command"`
	Evidence    []string  `json:"evidence"`
	Detail      string    `json:"detail"`
	Explanation string    `json:"explanation"`
	Action      string    `json:"action"`
	// Los textos de la regla y el detalle como texto (es/en); no viajan en el JSON.
	TitleTx, DetailTx, ExplanationTx, ActionTx i18n.Text `json:"-"`
}

type Options struct {
	Round  int    // 0 = todas; con N, las reglas de tendencia usan las rondas previas pero solo se reporta N
	Device string // parte del nombre o la IP del equipo
}

type Report struct {
	Dir      string    `json:"dir"`
	Devices  []string  `json:"devices"`
	Rounds   []int     `json:"rounds"`
	Findings []Finding `json:"findings"`
	Warnings []Warning `json:"warnings"`
	// Missing son comandos que las reglas necesitan y el trabajo no recolectó.
	Missing []string `json:"missing"`
}

// Analyze aplica las reglas a cada equipo del paquete.
func Analyze(b *Bundle, rules []Rule, o Options) Report {
	r := Report{Dir: b.Dir, Findings: []Finding{}, Warnings: []Warning{}, Missing: []string{}}
	warned := map[wkey]bool{}
	addWarn := func(w Warning) {
		if (o.Round == 0 || w.Round == 0 || w.Round == o.Round) && !warned[w.key()] {
			warned[w.key()] = true
			r.Warnings = append(r.Warnings, w)
		}
	}
	for _, w := range b.Warnings {
		if matchDevice(w.Device, o.Device) {
			addWarn(w)
		}
	}
	used := map[string]bool{}
	for _, dev := range b.Devices() {
		if !matchDevice(dev, o.Device) {
			continue
		}
		r.Devices = append(r.Devices, dev)
		for _, rule := range rules {
			series := seriesFor(b, dev, &rule, o.Round, addWarn)
			if len(series) == 0 {
				continue
			}
			used[rule.ID] = true
			at := map[int]Section{}
			for _, s := range series {
				at[s.Round] = s
			}
			for _, h := range rule.run(series, func(s Section, msg i18n.Text) {
				addWarn(warnTx(s.Device, s.Round, s.Command, msg))
			}) {
				if o.Round != 0 && h.round != o.Round {
					continue
				}
				s := at[h.round]
				r.Findings = append(r.Findings, Finding{Rule: rule.ID, Title: rule.Title, Severity: rule.Severity, Device: dev, Round: h.round,
					At: s.At, Command: s.Command, Evidence: h.evidence, Detail: h.detail.In(i18n.Es), Explanation: rule.Explanation, Action: rule.Action,
					TitleTx: rule.titleTx(), DetailTx: h.detail, ExplanationTx: rule.explanationTx(), ActionTx: rule.actionTx()})
			}
		}
	}
	r.Rounds = b.Rounds("")
	missing := map[string]bool{}
	for _, rule := range rules {
		if !used[rule.ID] {
			missing[rule.Commands[0]] = true
		}
	}
	r.Missing = append(r.Missing, sortedKeys(missing)...)
	sort.SliceStable(r.Findings, func(i, j int) bool {
		x, y := r.Findings[i], r.Findings[j]
		if sevRank[x.Severity] != sevRank[y.Severity] {
			return sevRank[x.Severity] > sevRank[y.Severity]
		}
		if x.Device != y.Device {
			return x.Device < y.Device
		}
		if x.Round != y.Round {
			return x.Round < y.Round
		}
		return x.Rule < y.Rule
	})
	return r
}

// seriesFor da la salida del comando de la regla por ronda (la primera si hay varias),
// hasta la ronda pedida. Un comando inválido en el equipo se avisa y se omite.
func seriesFor(b *Bundle, dev string, rule *Rule, upTo int, warn func(Warning)) []Section {
	var out []Section
	last := -1
	for _, s := range b.Sections {
		if s.Device != dev || !rule.matches(s.Command) || (upTo > 0 && s.Round > upTo) || s.Round == last {
			continue
		}
		if s.Invalid {
			warn(Warn(dev, s.Round, s.Command, "analyze.warn.rejected"))
			continue
		}
		out = append(out, s)
		last = s.Round
	}
	return out
}

// Text es el resumen legible para mctl, en español.
func (r Report) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el resumen en el idioma pedido (con es, el de siempre). El detalle, el título y demás textos de los
// hallazgos ya vienen en ese idioma si el informe pasó por i18n.Localize.
func (r Report) TextIn(loc string) string {
	var b strings.Builder
	m := func(key string, kv ...any) string { return i18n.Msg(loc, key, i18n.A(kv...)) }
	fmt.Fprintf(&b, "%s\n%s\n", r.Dir, m("analyze.text.summary", "devices", strings.Join(r.Devices, ", "), "rounds", r.Rounds, "n", len(r.Findings)))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n%s\n  %s\n", m("analyze.text.finding", "sev", m("analyze.sev."+f.Severity), "title", f.Title, "device", f.Device, "round", f.Round, "at", f.At.Format(time.RFC3339)), f.Detail)
		fmt.Fprintf(&b, "  %s\n", m("analyze.text.evidence", "cmd", f.Command))
		for _, ln := range f.Evidence {
			fmt.Fprintf(&b, "    | %s\n", ln)
		}
		fmt.Fprintf(&b, "  %s\n  %s\n", m("analyze.text.why", "text", f.Explanation), m("analyze.text.action", "text", f.Action))
	}
	if len(r.Missing) > 0 {
		fmt.Fprintf(&b, "\n%s\n", m("analyze.text.missing", "cmds", strings.Join(r.Missing, ", ")))
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "%s\n", m("analyze.text.warning", "message", w.in(loc)))
	}
	b.WriteString("\n" + m("analyze.text.unvalidated") + "\n")
	return b.String()
}

func (w Warning) String() string { return w.in(i18n.Es) }

// in es el aviso con su equipo, ronda y comando, en el idioma pedido (w.Msg ya debe estar en ese idioma).
func (w Warning) in(loc string) string {
	var p []string
	if w.Device != "" {
		p = append(p, w.Device)
	}
	if w.Round != 0 {
		p = append(p, i18n.Msg(loc, "analyze.text.round", i18n.A("round", w.Round)))
	}
	if w.Command != "" {
		p = append(p, w.Command)
	}
	if len(p) == 0 {
		return w.Msg
	}
	return strings.Join(p, " · ") + ": " + w.Msg
}
