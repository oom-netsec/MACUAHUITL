package logintel

import (
	"fmt"
	"sort"
	"strings"
	"time"
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
	Leaks     []Leak   `json:"leaks"`
	Processes int      `json:"processes"` // procesos con serie analizada (sin los agregados *Init*, *Dead*…)
	MinRounds int      `json:"min_rounds"`
	MinGrowth int64    `json:"min_growth"`
	Warnings  []string `json:"warnings,omitempty"`
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
		rep.Warnings = append(rep.Warnings, "no hay show processes memory en las rondas del trabajo")
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
			rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s: solo %d ronda(s) con show processes memory; hacen falta %d para ver una tendencia", h, len(rs), o.MinRounds))
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

// Text arma el informe legible.
func (r LeakReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d proceso(s) analizado(s); sospechoso = %d rondas seguidas sin bajar y +%s o más.\n", r.Processes, r.MinRounds, mib(r.MinGrowth))
	if len(r.Leaks) == 0 {
		b.WriteString("Ningún proceso con memoria creciente.\n")
	}
	for _, l := range r.Leaks {
		fmt.Fprintf(&b, "\n[FUGA POSIBLE] %s %s (pid %d): +%s (%s → %s) en rondas %d a %d", l.Host, l.Process, l.PID, mib(l.Growth), mib(l.Series[0]), mib(l.Series[len(l.Series)-1]), l.FromRound, l.ToRound)
		if l.PerHour > 0 {
			fmt.Fprintf(&b, ", unos %s por hora", mib(int64(l.PerHour)))
		}
		b.WriteByte('\n')
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\nAviso: %s\n", w)
	}
	return strings.TrimRight(b.String(), "\n")
}
