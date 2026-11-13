package logintel

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Proc es la memoria que retiene un proceso (columna Holding de show processes memory).
type Proc struct {
	PID     int
	Name    string
	Holding int64
}

// MemSample son los procesos de un equipo en una ronda de Patrol.
type MemSample struct {
	Host  string
	Round int
	At    time.Time
	Procs []Proc
}

// LeakOptions: un proceso es sospechoso si, en al menos MinRounds rondas seguidas, nunca baja y
// al menos la mitad de los pasos sube, con un crecimiento total de MinGrowth bytes o más.
type LeakOptions struct {
	MinRounds int
	MinGrowth int64
}

// Leak es un proceso cuya memoria crece en forma monótona.
type Leak struct {
	Host      string  `json:"host"`
	Process   string  `json:"process"`
	PID       int     `json:"pid"`
	Rounds    int     `json:"rounds"`
	FromRound int     `json:"from_round"`
	ToRound   int     `json:"to_round"`
	Series    []int64 `json:"series"`
	Growth    int64   `json:"growth"`
	PerHour   float64 `json:"per_hour,omitempty"` // 0 si las rondas no traen hora
}

type LeakReport struct {
	Leaks     []Leak      `json:"leaks"`
	Processes int         `json:"processes"` // procesos con serie analizada (sin los agregados *Init*, *Dead*…)
	MinRounds int         `json:"min_rounds"`
	MinGrowth int64       `json:"min_growth"`
	Warnings  []string    `json:"warnings,omitempty"`
	WarnT     []i18n.Text `json:"-"` // los Warnings como texto de catálogo, en paralelo
}

type procKey struct {
	host string
	pid  int
	name string
}

type point struct {
	round int
	at    time.Time
	v     int64
}

// MemLeaks busca procesos con memoria creciente entre rondas. El PID es parte de la identidad: un
// proceso que se reinició con otro PID empieza una serie nueva. Los nombres que empiezan con "*"
// (*Init*, *Dead*, *Sched*) son agregados del sistema, no procesos, y se omiten.
func MemLeaks(ss []MemSample, o LeakOptions) LeakReport {
	if o.MinRounds <= 0 {
		o.MinRounds = 3
	}
	if o.MinGrowth <= 0 {
		o.MinGrowth = 1 << 20
	}
	rep := LeakReport{Leaks: []Leak{}, MinRounds: o.MinRounds, MinGrowth: o.MinGrowth}
	if len(ss) == 0 {
		i18n.Note(&rep.Warnings, &rep.WarnT, "logintel.leak.no_data")
		return rep
	}
	series := map[procKey][]point{}
	lastRound := map[string]int{}
	rounds := map[string]map[int]bool{}
	for _, s := range ss {
		lastRound[s.Host] = max(lastRound[s.Host], s.Round)
		if rounds[s.Host] == nil {
			rounds[s.Host] = map[int]bool{}
		}
		rounds[s.Host][s.Round] = true
		for _, p := range s.Procs {
			if strings.HasPrefix(p.Name, "*") {
				continue
			}
			k := procKey{s.Host, p.PID, p.Name}
			series[k] = append(series[k], point{s.Round, s.At, p.Holding})
		}
	}
	hosts := make([]string, 0, len(rounds))
	for h, rs := range rounds {
		hosts = append(hosts, h)
		if len(rs) < o.MinRounds {
			i18n.Note(&rep.Warnings, &rep.WarnT, "logintel.leak.few", "host", h, "n", len(rs), "min", o.MinRounds)
		}
	}
	sort.Strings(hosts)
	rep.Processes = len(series)
	for k, pts := range series {
		sort.Slice(pts, func(i, j int) bool { return pts[i].round < pts[j].round })
		if pts[len(pts)-1].round != lastRound[k.host] {
			continue // ya no está: terminó o se reinició
		}
		i := len(pts) - 1 // el tramo final que no baja
		for i > 0 && pts[i-1].v <= pts[i].v {
			i--
		}
		run := pts[i:]
		n := len(run)
		if n < o.MinRounds {
			continue
		}
		up := 0
		for j := 1; j < n; j++ {
			if run[j].v > run[j-1].v {
				up++
			}
		}
		growth := run[n-1].v - run[0].v
		if growth < o.MinGrowth || up*2 < n-1 {
			continue
		}
		l := Leak{Host: k.host, Process: k.name, PID: k.pid, Rounds: n, FromRound: run[0].round, ToRound: run[n-1].round, Growth: growth}
		for _, p := range run {
			l.Series = append(l.Series, p.v)
		}
		if d := run[n-1].at.Sub(run[0].at); !run[0].at.IsZero() && !run[n-1].at.IsZero() && d > 0 {
			l.PerHour = float64(growth) / d.Hours()
		}
		rep.Leaks = append(rep.Leaks, l)
	}
	sort.Slice(rep.Leaks, func(i, j int) bool {
		a, b := rep.Leaks[i], rep.Leaks[j]
		switch {
		case a.Growth != b.Growth:
			return a.Growth > b.Growth
		case a.Host != b.Host:
			return a.Host < b.Host
		}
		return a.Process < b.Process
	})
	return rep
}

func mib(b int64) string { return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20)) }

// Localize da el informe con los avisos en el idioma dado (con es, tal cual).
func (r LeakReport) Localize(loc string) LeakReport {
	r.Warnings = i18n.Notes(loc, r.Warnings, r.WarnT)
	return r
}

// Text arma el informe legible en español.
func (r LeakReport) Text() string { return r.TextIn(i18n.Es) }

// TextIn arma el informe legible en el idioma dado (r ya viene en ese idioma: ver Localize).
func (r LeakReport) TextIn(loc string) string {
	var b strings.Builder
	m := func(k string, kv ...any) string { return i18n.Msg(loc, k, i18n.A(kv...)) }
	b.WriteString(m("logintel.leak.head", "n", r.Processes, "rounds", r.MinRounds, "growth", mib(r.MinGrowth)) + "\n")
	if len(r.Leaks) == 0 {
		b.WriteString(m("logintel.leak.none") + "\n")
	}
	for _, l := range r.Leaks {
		b.WriteString("\n" + m("logintel.leak.line", "host", l.Host, "process", l.Process, "pid", l.PID, "growth", mib(l.Growth), "from", mib(l.Series[0]), "to", mib(l.Series[len(l.Series)-1]), "from_round", l.FromRound, "to_round", l.ToRound))
		if l.PerHour > 0 {
			b.WriteString(m("logintel.leak.per_hour", "rate", mib(int64(l.PerHour))))
		}
		b.WriteByte('\n')
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\n%s: %s\n", m("forensic.label.warning"), w)
	}
	return strings.TrimRight(b.String(), "\n")
}
