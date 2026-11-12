package logintel

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/msgkb"
)

// GroupOptions: ráfaga = BurstCount mensajes del mismo patrón dentro de BurstWindow.
type GroupOptions struct {
	BurstCount  int
	BurstWindow time.Duration
	MaxPatterns int
}

func (o GroupOptions) norm() GroupOptions {
	if o.BurstCount <= 0 {
		o.BurstCount = 5
	}
	if o.BurstWindow <= 0 {
		o.BurstWindow = 60 * time.Second
	}
	if o.MaxPatterns <= 0 || o.MaxPatterns > 2000 {
		o.MaxPatterns = 2000
	}
	return o
}

const maxHosts = 10

// Pattern es un grupo de mensajes con el mismo patrón normalizado.
type Pattern struct {
	Pattern   string       `json:"pattern"`
	Mnemonic  string       `json:"mnemonic,omitempty"`
	Severity  int          `json:"severity"`
	Count     int          `json:"count"`
	First     time.Time    `json:"first,omitzero"`
	Last      time.Time    `json:"last,omitzero"`
	Hosts     []string     `json:"hosts,omitempty"` // hasta 10
	HostCount int          `json:"host_count"`
	Example   string       `json:"example"`
	Peak      int          `json:"peak"`     // más mensajes vistos dentro de una ventana
	Episodes  int          `json:"episodes"` // veces que se llegó al umbral de ráfaga
	Burst     bool         `json:"burst"`
	Unstable  bool         `json:"unstable"` // dos o más ráfagas separadas: el problema vuelve
	KB        *msgkb.Entry `json:"-"`        // la ficha viaja una vez por mnemónico en Report.KB
}

// Report es el resultado de agrupar.
type Report struct {
	Entries     int       `json:"entries"`
	WithTime    int       `json:"with_time"`
	Patterns    []Pattern `json:"patterns"`
	Overflow    int       `json:"overflow,omitempty"` // mensajes de patrones que no cupieron
	BurstCount  int       `json:"burst_count"`
	BurstWindow string    `json:"burst_window"`
	Warnings    []string  `json:"warnings,omitempty"`
	// KB: la ficha de la base de mensajes por mnemónico, una vez, no repetida en cada patrón.
	KB map[string]msgkb.Entry `json:"kb,omitempty"`
}

type acc struct {
	p     Pattern
	hosts map[string]bool
	times []time.Time
}

// Group agrupa por patrón, cuenta y detecta ráfagas. Las ráfagas se miden sobre todo el patrón
// (todos los equipos juntos): sirve para ver un problema que se repite en la red.
func Group(es []Entry, o GroupOptions) Report {
	o = o.norm()
	rep := Report{Entries: len(es), Patterns: []Pattern{}, BurstCount: o.BurstCount, BurstWindow: o.BurstWindow.String()}
	groups := map[string]*acc{}
	for _, e := range es {
		key := Normalize(e.Text)
		a := groups[key]
		if a == nil {
			if len(groups) >= o.MaxPatterns {
				rep.Overflow++
				continue
			}
			a = &acc{p: Pattern{Pattern: key, Mnemonic: e.Mnemonic, Severity: e.Severity, Example: e.Text}, hosts: map[string]bool{}}
			groups[key] = a
		}
		a.p.Count++
		if e.Severity >= 0 && (a.p.Severity < 0 || e.Severity < a.p.Severity) {
			a.p.Severity = e.Severity
		}
		if len(a.hosts) < 1000 {
			a.hosts[e.Host] = true
		}
		if !e.At.IsZero() {
			rep.WithTime++
			a.times = append(a.times, e.At)
		}
	}
	kb, _ := msgkb.Default()
	for _, a := range groups {
		a.finish(o, kb)
		rep.Patterns = append(rep.Patterns, a.p)
		if a.p.KB != nil {
			if rep.KB == nil {
				rep.KB = map[string]msgkb.Entry{}
			}
			rep.KB[a.p.Mnemonic] = *a.p.KB
		}
	}
	sort.Slice(rep.Patterns, func(i, j int) bool {
		a, b := rep.Patterns[i], rep.Patterns[j]
		switch {
		case a.Unstable != b.Unstable:
			return a.Unstable
		case a.Burst != b.Burst:
			return a.Burst
		case a.Count != b.Count:
			return a.Count > b.Count
		}
		return a.Pattern < b.Pattern
	})
	if n := len(es) - rep.WithTime; n > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("%d mensaje(s) sin hora: se agrupan y cuentan, pero no entran en la detección de ráfagas", n))
	}
	if rep.Overflow > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("hay más de %d patrones distintos: %d mensaje(s) de patrones nuevos no se agruparon", o.MaxPatterns, rep.Overflow))
	}
	return rep
}

func (a *acc) finish(o GroupOptions, kb *msgkb.KB) {
	p := &a.p
	p.HostCount = len(a.hosts)
	for h := range a.hosts {
		if h != "" {
			p.Hosts = append(p.Hosts, h)
		}
	}
	sort.Strings(p.Hosts)
	if len(p.Hosts) > maxHosts {
		p.Hosts = p.Hosts[:maxHosts]
	}
	sort.Slice(a.times, func(i, j int) bool { return a.times[i].Before(a.times[j]) })
	if n := len(a.times); n > 0 {
		p.First, p.Last = a.times[0], a.times[n-1]
	}
	p.Peak, p.Episodes = peaks(a.times, o.BurstWindow, o.BurstCount)
	p.Burst, p.Unstable = p.Episodes >= 1, p.Episodes >= 2
	if kb != nil && p.Mnemonic != "" {
		if e, ok := kb.Lookup(p.Mnemonic); ok {
			p.KB = &e
		}
	}
}

// Text arma el informe legible de los patrones.
func (r Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d mensaje(s) en %d patrón(es). Ráfaga: %d del mismo patrón en %s.\n", r.Entries, len(r.Patterns), r.BurstCount, r.BurstWindow)
	for _, p := range r.Patterns {
		tag := ""
		switch {
		case p.Unstable:
			tag = "[INESTABLE] "
		case p.Burst:
			tag = "[RÁFAGA] "
		}
		fmt.Fprintf(&b, "\n%sx%d  %s\n", tag, p.Count, p.Pattern)
		if p.Peak > 0 {
			fmt.Fprintf(&b, "    pico: %d en la ventana; ráfagas: %d\n", p.Peak, p.Episodes)
		}
		if !p.First.IsZero() {
			fmt.Fprintf(&b, "    de %s a %s\n", p.First.UTC().Format(time.RFC3339), p.Last.UTC().Format(time.RFC3339))
		}
		if p.HostCount > 0 {
			fmt.Fprintf(&b, "    equipos (%d): %s\n", p.HostCount, strings.Join(p.Hosts, ", "))
		}
		fmt.Fprintf(&b, "    ejemplo: %s\n", p.Example)
		if p.KB != nil {
			fmt.Fprintf(&b, "    base de mensajes: %s Acción: %s\n", p.KB.Meaning, p.KB.Action)
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\nAviso: %s\n", w)
	}
	return strings.TrimRight(b.String(), "\n")
}
