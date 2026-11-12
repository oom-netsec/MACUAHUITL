package analyze

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"gopkg.in/yaml.v3"
)

// Las reglas viven en rules/*.yaml, versionadas con el código e incrustadas en el binario.
//
//go:embed rules/*.yaml
var rulesFS embed.FS

// Rule es una regla declarativa: qué comando mira, qué verificación aplica
// (check + params) y qué decirle al ingeniero.
type Rule struct {
	ID          string            `yaml:"id"`
	Title       string            `yaml:"title"`
	Severity    string            `yaml:"severity"`
	Commands    []string          `yaml:"commands"`
	Check       string            `yaml:"check"`
	Params      map[string]string `yaml:"params"`
	Explanation string            `yaml:"explanation"`
	Action      string            `yaml:"action"`
	run         checker
}

var sevRank = map[string]int{"critica": 5, "alta": 4, "media": 3, "baja": 2, "info": 1}

// hit es lo que encuentra una verificación: ronda, líneas exactas y detalle.
type hit struct {
	round    int
	evidence []string
	detail   string
}

// checker recorre las salidas del comando de un equipo, una por ronda y en orden.
type checker func(series []Section, warn func(s Section, msg string)) []hit

// DefaultRules carga las reglas incrustadas.
func DefaultRules() ([]Rule, error) {
	sub, err := fs.Sub(rulesFS, "rules")
	if err != nil {
		return nil, err
	}
	return LoadRules(sub)
}

// LoadRules lee todos los *.yaml de fsys; un archivo inválido devuelve error con su nombre.
func LoadRules(fsys fs.FS) ([]Rule, error) {
	var out []Rule
	ids := map[string]bool{}
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(name) != ".yaml" {
			return err
		}
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		var rs []Rule
		dec := yaml.NewDecoder(bytes.NewReader(b))
		dec.KnownFields(true)
		if err := dec.Decode(&rs); err != nil {
			return fmt.Errorf("reglas %s: %w", name, err)
		}
		for _, r := range rs {
			if err := r.compile(); err != nil {
				return fmt.Errorf("reglas %s: %s: %w", name, r.ID, err)
			}
			if ids[r.ID] {
				return fmt.Errorf("reglas %s: id %s repetido", name, r.ID)
			}
			ids[r.ID] = true
			out = append(out, r)
		}
		return nil
	})
	return out, err
}

func (r *Rule) compile() error {
	switch {
	case r.ID == "" || r.Title == "" || r.Explanation == "" || r.Action == "":
		return errors.New("id, title, explanation y action son obligatorios")
	case sevRank[r.Severity] == 0:
		return fmt.Errorf("severidad %q inválida (critica, alta, media, baja, info)", r.Severity)
	case len(r.Commands) == 0:
		return errors.New("sin comandos")
	}
	for i, c := range r.Commands {
		r.Commands[i] = normCmd(c)
	}
	mk, ok := checks[r.Check]
	if !ok {
		return fmt.Errorf("check %q desconocido", r.Check)
	}
	p := &params{m: r.Params, used: map[string]bool{}}
	run, err := mk(p)
	if err != nil {
		return err
	}
	for k := range r.Params {
		if !p.used[k] {
			return fmt.Errorf("parámetro %q no aplica a %s", k, r.Check)
		}
	}
	r.run = run
	return nil
}

func normCmd(c string) string { return strings.ToLower(strings.Join(strings.Fields(c), " ")) }

// matches acepta el comando exacto o filtrado ("show logging | include LINK").
// shortcut: no reconoce abreviaturas ("sh proc cpu"); los playbooks usan el comando completo.
func (r *Rule) matches(cmd string) bool {
	c := normCmd(cmd)
	for _, x := range r.Commands {
		if c == x || strings.HasPrefix(c, x+" |") {
			return true
		}
	}
	return false
}

type params struct {
	m    map[string]string
	used map[string]bool
}

func (p *params) get(k string) (string, bool) {
	p.used[k] = true
	v, ok := p.m[k]
	return v, ok
}

func (p *params) num(k string, def float64) (float64, error) {
	v, ok := p.get(k)
	if !ok {
		return def, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("parámetro %s: %q no es un número", k, v)
	}
	return f, nil
}

func (p *params) dur(k string, def time.Duration) (time.Duration, error) {
	v, ok := p.get(k)
	if !ok {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("parámetro %s: %q no es una duración", k, v)
	}
	return d, nil
}

func (p *params) flag(k string) (bool, error) {
	v, ok := p.get(k)
	if !ok {
		return false, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("parámetro %s: %q no es true/false", k, v)
	}
	return b, nil
}

func (p *params) oneOf(k string, opts ...string) (string, error) {
	v, _ := p.get(k)
	for _, o := range opts {
		if v == o {
			return v, nil
		}
	}
	return "", fmt.Errorf("parámetro %s: %q debe ser uno de %v", k, v, opts)
}

var checks = map[string]func(*params) (checker, error){
	"match":          checkMatch,
	"cpu_high":       checkCPUHigh,
	"cpu_trend":      checkCPUTrend,
	"mem_low":        checkMemLow,
	"mem_leak":       checkMemLeak,
	"iface_counter":  checkIfaceCounter,
	"uptime":         checkUptime,
	"uptime_reset":   checkUptimeReset,
	"stp_changes":    checkSTP,
	"bgp_neighbors":  checkBGP,
	"ospf_neighbors": checkOSPF,
	"hsrp":           checkHSRP,
}

const formatoInesperado = "formato inesperado: sin datos para esta regla"

// checkMatch busca líneas por expresión regular. Un mensaje ya reportado en una
// ronda anterior no se repite (el búfer de log se arrastra entre rondas).
// Con group, cuenta por el primer grupo de captura (p. ej. la interfaz).
func checkMatch(p *params) (checker, error) {
	pat, _ := p.get("pattern")
	re, err := regexp.Compile(pat)
	if err != nil || pat == "" {
		return nil, fmt.Errorf("pattern inválido: %v", err)
	}
	var ex *regexp.Regexp
	if v, ok := p.get("exclude"); ok {
		if ex, err = regexp.Compile(v); err != nil {
			return nil, fmt.Errorf("exclude inválido: %w", err)
		}
	}
	minF, err := p.num("min", 1)
	if err != nil {
		return nil, err
	}
	group, err := p.flag("group")
	if err != nil {
		return nil, err
	}
	if group && re.NumSubexp() < 1 {
		return nil, errors.New("group requiere un grupo de captura en pattern")
	}
	min := int(minF)
	return func(series []Section, _ func(Section, string)) []hit {
		seen := map[string]bool{}
		var out []hit
		for _, s := range series {
			groups := map[string][]string{}
			for _, ln := range lines(s.Text) {
				m := re.FindStringSubmatch(ln)
				if m == nil || ex != nil && ex.MatchString(ln) {
					continue
				}
				g := ""
				if group {
					g = m[1]
				}
				groups[g] = append(groups[g], ln)
			}
			var ev, det []string
			for _, g := range sortedKeys(groups) {
				ls := groups[g]
				fresh := false
				for _, ln := range ls {
					fresh = fresh || !seen[ln]
				}
				if len(ls) < min || !fresh {
					continue
				}
				for _, ln := range ls {
					if group || !seen[ln] {
						ev = append(ev, ln)
					}
					seen[ln] = true
				}
				if group {
					det = append(det, fmt.Sprintf("%s: %d veces", g, len(ls)))
				}
			}
			if len(ev) > 0 {
				d := strings.Join(det, "; ")
				if !group {
					d = fmt.Sprintf("%d línea(s)", len(ev))
				}
				out = append(out, hit{round: s.Round, evidence: ev, detail: d})
			}
		}
		return out
	}, nil
}

func checkCPUHigh(p *params) (checker, error) {
	above, err := p.num("above", 80)
	if err != nil {
		return nil, err
	}
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		for _, s := range series {
			c, ok := iosxe.ParseCPU(s.Text)
			if !ok {
				warn(s, formatoInesperado+` (falta "CPU utilization for five seconds")`)
				continue
			}
			if c.FiveMin >= above {
				out = append(out, hit{s.Round, []string{c.Line}, fmt.Sprintf("5 min: %.0f%% (umbral %.0f%%)", c.FiveMin, above)})
			}
		}
		return out
	}, nil
}

// trend busca rachas estrictamente monótonas de al menos n rondas con salida
// legible (una ronda omitida no corta la racha; una ilegible sí). up=true sube; up=false baja. Devuelve, por ronda final, la racha.
func trend[T any](series []Section, parse func(string) (T, bool), val func(T) float64, up bool, n int, warn func(Section, string)) map[int][]T {
	out := map[int][]T{}
	var run []T
	for _, s := range series {
		v, ok := parse(s.Text)
		if !ok {
			warn(s, formatoInesperado)
			run = nil
			continue
		}
		if len(run) > 0 && (up && val(v) > val(run[len(run)-1]) || !up && val(v) < val(run[len(run)-1])) {
			run = append(run, v)
		} else {
			run = []T{v}
		}
		if len(run) >= n {
			out[s.Round] = append([]T(nil), run...)
		}
	}
	return out
}

func checkCPUTrend(p *params) (checker, error) {
	rounds, err := p.num("rounds", 3)
	if err != nil {
		return nil, err
	}
	rise, err := p.num("rise", 20)
	if err != nil {
		return nil, err
	}
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		runs := trend(series, iosxe.ParseCPU, func(c iosxe.CPU) float64 { return c.FiveMin }, true, int(rounds), warn)
		for _, s := range series {
			run := runs[s.Round]
			if run == nil || run[len(run)-1].FiveMin-run[0].FiveMin < rise {
				continue
			}
			var vals []string
			for _, c := range run {
				vals = append(vals, fmt.Sprintf("%.0f%%", c.FiveMin))
			}
			out = append(out, hit{s.Round, []string{run[len(run)-1].Line}, "5 min por ronda: " + strings.Join(vals, " → ")})
		}
		return out
	}, nil
}

func pct(m iosxe.Mem) float64 { return float64(m.Free) * 100 / float64(m.Total) }

func checkMemLow(p *params) (checker, error) {
	below, err := p.num("below", 10)
	if err != nil {
		return nil, err
	}
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		for _, s := range series {
			m, ok := iosxe.ParseMem(s.Text)
			if !ok {
				warn(s, formatoInesperado+" (falta el pool Processor)")
				continue
			}
			if pct(m) < below {
				out = append(out, hit{s.Round, []string{m.Line}, fmt.Sprintf("libre %.1f%% de %d bytes (umbral %.0f%%)", pct(m), m.Total, below)})
			}
		}
		return out
	}, nil
}

func checkMemLeak(p *params) (checker, error) {
	rounds, err := p.num("rounds", 3)
	if err != nil {
		return nil, err
	}
	drop, err := p.num("drop", 5)
	if err != nil {
		return nil, err
	}
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		runs := trend(series, iosxe.ParseMem, func(m iosxe.Mem) float64 { return float64(m.Free) }, false, int(rounds), warn)
		for _, s := range series {
			run := runs[s.Round]
			if run == nil {
				continue
			}
			first, last := run[0], run[len(run)-1]
			lost := float64(first.Free-last.Free) * 100 / float64(last.Total)
			if lost < drop {
				continue
			}
			var vals []string
			for _, m := range run {
				vals = append(vals, fmt.Sprintf("%.1f%%", pct(m)))
			}
			out = append(out, hit{s.Round, []string{last.Line}, fmt.Sprintf("libre por ronda: %s (bajó %.1f puntos)", strings.Join(vals, " → "), lost)})
		}
		return out
	}, nil
}

func checkIfaceCounter(p *params) (checker, error) {
	counter, err := p.oneOf("counter", CounterNames...)
	if err != nil {
		return nil, err
	}
	growing, err := p.flag("growing")
	if err != nil {
		return nil, err
	}
	minF, err := p.num("min", 1)
	if err != nil {
		return nil, err
	}
	min := int64(minF)
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		reported := map[string]bool{}
		var prev map[string]int64
		prevRound := 0
		for _, s := range series {
			ifs, ok := parseInterfaces(s.Text)
			if !ok {
				warn(s, formatoInesperado+" (ninguna interfaz reconocida)")
				prev = nil
				continue
			}
			cur := map[string]int64{}
			var ev, det []string
			for _, i := range ifs {
				v, ok := i.Values[counter]
				if !ok {
					continue
				}
				cur[i.Name] = v
				if growing {
					// Solo entre rondas consecutivas; si el contador bajó, se borró o el equipo recargó.
					if pv, ok := prev[i.Name]; ok && prevRound == s.Round-1 && v-pv >= min {
						ev = append(ev, i.Lines[counter])
						det = append(det, fmt.Sprintf("%s: %d → %d (+%d)", i.Name, pv, v, v-pv))
					}
				} else if v >= min && !reported[i.Name] {
					reported[i.Name] = true
					ev = append(ev, i.Lines[counter])
					det = append(det, fmt.Sprintf("%s: %d", i.Name, v))
				}
			}
			if len(ev) > 0 {
				out = append(out, hit{s.Round, dedupe(ev), counter + " — " + strings.Join(det, "; ")})
			}
			prev, prevRound = cur, s.Round
		}
		return out
	}, nil
}

// dedupe quita líneas repetidas conservando el orden (dos interfaces pueden compartir texto).
func dedupe(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func fmtDur(d time.Duration) string {
	if d < time.Minute {
		return d.String()
	}
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	s := ""
	if days > 0 {
		s = fmt.Sprintf("%dd", days)
	}
	return s + fmt.Sprintf("%dh%02dm", d/time.Hour, (d%time.Hour)/time.Minute)
}

func checkUptime(p *params) (checker, error) {
	below, err := p.dur("below", 24*time.Hour)
	if err != nil {
		return nil, err
	}
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		for _, s := range series {
			u, ok := parseUptime(s.Text)
			if !ok {
				warn(s, formatoInesperado+` (falta "uptime is")`)
				continue
			}
			if u.D < below {
				out = append(out, hit{s.Round, append([]string{u.Line}, u.Reasons...), "arriba desde hace " + fmtDur(u.D)})
			}
		}
		return out
	}, nil
}

func checkUptimeReset(*params) (checker, error) {
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		var prev *uptimeInfo
		for _, s := range series {
			u, ok := parseUptime(s.Text)
			if !ok {
				warn(s, formatoInesperado+` (falta "uptime is")`)
				prev = nil
				continue
			}
			if prev != nil && u.D < prev.D {
				out = append(out, hit{s.Round, append([]string{u.Line}, u.Reasons...), fmt.Sprintf("uptime %s → %s", fmtDur(prev.D), fmtDur(u.D))})
			}
			prev = &u
		}
		return out
	}, nil
}

func checkSTP(p *params) (checker, error) {
	minF, err := p.num("min_delta", 1)
	if err != nil {
		return nil, err
	}
	recent, err := p.dur("recent", 5*time.Minute)
	if err != nil {
		return nil, err
	}
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		prev := map[string]int64{}
		for _, s := range series {
			insts, ok := iosxe.ParseSTPDetail(s.Text)
			if !ok {
				warn(s, formatoInesperado+` (falta "Number of topology changes")`)
				prev = map[string]int64{}
				continue
			}
			var ev, det []string
			cur := map[string]int64{}
			for _, i := range insts {
				cur[i.Name] = i.Changes
				pv, had := prev[i.Name]
				grew := had && i.Changes >= pv && float64(i.Changes-pv) >= minF
				fresh := i.SinceOK && i.Since < recent
				if !grew && !fresh {
					continue
				}
				ev = append(ev, i.Lines...)
				d := fmt.Sprintf("%s: %d cambios", i.Name, i.Changes)
				if had {
					d = fmt.Sprintf("%s: %d → %d cambios", i.Name, pv, i.Changes)
				}
				if i.SinceOK {
					d += ", último hace " + i.Since.String()
				}
				if i.From != "" {
					d += " desde " + i.From
				}
				det = append(det, d)
			}
			if len(ev) > 0 {
				out = append(out, hit{s.Round, ev, strings.Join(det, "; ")})
			}
			prev = cur
		}
		return out
	}, nil
}

func checkBGP(p *params) (checker, error) {
	mode, err := p.oneOf("mode", "down", "flap")
	if err != nil {
		return nil, err
	}
	below, err := p.dur("below", time.Hour)
	if err != nil {
		return nil, err
	}
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		for _, s := range series {
			ns, ok := iosxe.ParseBGP(s.Text)
			if !ok {
				warn(s, formatoInesperado+" (falta la tabla de vecinos)")
				continue
			}
			var ev, det []string
			for _, n := range ns {
				switch {
				case mode == "down" && !n.Established && !strings.Contains(n.State, "Admin"):
					ev, det = append(ev, n.Lines...), append(det, fmt.Sprintf("%s (AS %s): %s desde hace %s", n.ID, n.AS, n.State, n.UpDown))
				case mode == "flap" && n.Established:
					if d, ok := iosxe.IOSDuration(n.UpDown); ok && d < below {
						ev, det = append(ev, n.Lines...), append(det, fmt.Sprintf("%s (AS %s): arriba hace %s", n.ID, n.AS, n.UpDown))
					}
				}
			}
			if len(ev) > 0 {
				out = append(out, hit{s.Round, ev, strings.Join(det, "; ")})
			}
		}
		return out
	}, nil
}

func checkOSPF(p *params) (checker, error) {
	mode, err := p.oneOf("mode", "stuck", "lost")
	if err != nil {
		return nil, err
	}
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		var prev map[string]iosxe.OSPFNeighbor
		prevRound := 0
		for _, s := range series {
			ns, ok := iosxe.ParseOSPF(s.Text)
			if !ok {
				warn(s, formatoInesperado+" (falta la tabla de vecinos)")
				prev = nil
				continue
			}
			cur := map[string]iosxe.OSPFNeighbor{}
			var ev, det []string
			for _, n := range ns {
				cur[ospfKey(n)] = n
				if mode == "stuck" && n.State != "FULL" && n.State != "2WAY" {
					ev, det = append(ev, n.Line), append(det, fmt.Sprintf("%s en %s por %s", n.ID, n.State, n.Interface))
				}
			}
			if mode == "lost" && prev != nil && prevRound == s.Round-1 {
				for _, k := range sortedKeys(prev) {
					if _, ok := cur[k]; !ok {
						det = append(det, fmt.Sprintf("%s estaba en la ronda %d y ya no aparece", k, prevRound))
					}
				}
				if len(det) > 0 {
					// La evidencia es la tabla actual: el vecino perdido es justo lo que falta en ella.
					for _, n := range ns {
						ev = append(ev, n.Line)
					}
					if len(ev) == 0 {
						ev = []string{strings.TrimSpace(firstMatch(s.Text, ospfHeaderRe))}
					}
				}
			}
			if len(det) > 0 {
				out = append(out, hit{s.Round, ev, strings.Join(det, "; ")})
			}
			prev, prevRound = cur, s.Round
		}
		return out
	}, nil
}

func firstMatch(text string, re *regexp.Regexp) string {
	for _, ln := range lines(text) {
		if re.MatchString(ln) {
			return ln
		}
	}
	return ""
}

var hsrpBad = map[string]bool{"init": true, "learn": true, "speak": true}

func checkHSRP(p *params) (checker, error) {
	mode, err := p.oneOf("mode", "changed", "bad")
	if err != nil {
		return nil, err
	}
	return func(series []Section, warn func(Section, string)) []hit {
		var out []hit
		var prev map[string]string
		prevRound := 0
		for _, s := range series {
			gs, ok := iosxe.ParseHSRP(s.Text)
			if !ok {
				warn(s, formatoInesperado+" (falta la tabla de grupos)")
				prev = nil
				continue
			}
			cur := map[string]string{}
			var ev, det []string
			for _, g := range gs {
				cur[hsrpKey(g)] = g.State
				switch {
				case mode == "changed" && prev != nil && prevRound == s.Round-1:
					if ps, ok := prev[hsrpKey(g)]; ok && ps != g.State {
						ev, det = append(ev, g.Line), append(det, fmt.Sprintf("%s: %s → %s", hsrpKey(g), ps, g.State))
					}
				case mode == "bad" && (hsrpBad[strings.ToLower(g.State)] || g.Active == "unknown" || g.Standby == "unknown"):
					ev, det = append(ev, g.Line), append(det, fmt.Sprintf("%s: %s (activo %s, respaldo %s)", hsrpKey(g), g.State, g.Active, g.Standby))
				}
			}
			if len(ev) > 0 {
				out = append(out, hit{s.Round, ev, strings.Join(det, "; ")})
			}
			prev, prevRound = cur, s.Round
		}
		return out
	}, nil
}
