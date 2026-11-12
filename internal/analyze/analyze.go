package analyze

import (
	"fmt"
	"sort"
	"strings"
	"time"
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
	warned := map[Warning]bool{}
	addWarn := func(w Warning) {
		if (o.Round == 0 || w.Round == 0 || w.Round == o.Round) && !warned[w] {
			warned[w] = true
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
			for _, h := range rule.run(series, func(s Section, msg string) {
				addWarn(Warning{Device: s.Device, Round: s.Round, Command: s.Command, Msg: msg})
			}) {
				if o.Round != 0 && h.round != o.Round {
					continue
				}
				s := at[h.round]
				r.Findings = append(r.Findings, Finding{Rule: rule.ID, Title: rule.Title, Severity: rule.Severity, Device: dev, Round: h.round,
					At: s.At, Command: s.Command, Evidence: h.evidence, Detail: h.detail, Explanation: rule.Explanation, Action: rule.Action})
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
			warn(Warning{Device: dev, Round: s.Round, Command: s.Command, Msg: "el equipo rechazó el comando; sin datos para las reglas que lo usan"})
			continue
		}
		out = append(out, s)
		last = s.Round
	}
	return out
}

var sevLabel = map[string]string{"critica": "CRÍTICA", "alta": "ALTA", "media": "MEDIA", "baja": "BAJA", "info": "INFO"}

// Text es el resumen legible para mctl.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\nequipos: %s · rondas: %v · hallazgos: %d\n", r.Dir, strings.Join(r.Devices, ", "), r.Rounds, len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n[%s] %s — %s · ronda %d · %s\n  %s\n", sevLabel[f.Severity], f.Title, f.Device, f.Round, f.At.Format(time.RFC3339), f.Detail)
		fmt.Fprintf(&b, "  evidencia (%s):\n", f.Command)
		for _, ln := range f.Evidence {
			fmt.Fprintf(&b, "    | %s\n", ln)
		}
		fmt.Fprintf(&b, "  por qué: %s\n  qué hacer: %s\n", f.Explanation, f.Action)
	}
	if len(r.Missing) > 0 {
		fmt.Fprintf(&b, "\nno recolectados (reglas sin datos): %s\n", strings.Join(r.Missing, ", "))
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "aviso: %s\n", w.String())
	}
	b.WriteString("\nReglas sin validar en laboratorio: confirma cada hallazgo con la evidencia.\n")
	return b.String()
}

func (w Warning) String() string {
	var p []string
	if w.Device != "" {
		p = append(p, w.Device)
	}
	if w.Round != 0 {
		p = append(p, fmt.Sprintf("ronda %d", w.Round))
	}
	if w.Command != "" {
		p = append(p, w.Command)
	}
	if len(p) == 0 {
		return w.Msg
	}
	return strings.Join(p, " · ") + ": " + w.Msg
}
