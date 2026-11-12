package metrics

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Topes por omisión y máximos: una serie de 24 h con rondas de un minuto son 1 440 puntos por
// interfaz; sin tope, un trabajo largo con 48 puertos devolvería cientos de miles de puntos.
const (
	DefaultMaxPoints = 500
	MaxPoints        = 5000
	DefaultMaxIfaces = 12
	MaxIfaces        = 64
	// rebootSlack absorbe que el uptime de IOS solo tiene precisión de minutos.
	rebootSlack = 2 * time.Minute
)

type Options struct {
	Device    string   // dirección o nombre; vacío = todos
	MaxPoints int      // 0 = DefaultMaxPoints; se queda con las rondas más recientes
	MaxIfaces int      // 0 = DefaultMaxIfaces; las de mayor utilización pico
	Ifaces    []string // interfaces concretas (en cualquier forma: Gi1/0/1, GigabitEthernet1/0/1); anula MaxIfaces
}

type CPUPoint struct {
	Round                 int
	At                    time.Time
	Five, OneMin, FiveMin float64
}

type MemPoint struct {
	Round             int
	At                time.Time
	Used, Free, Total int64
}

type MemSeries struct {
	Pool   string
	Points []MemPoint
}

type IfPoint struct {
	Round int
	At    time.Time
	// InBps y OutBps vienen de la diferencia de contadores entre rondas (Source "counters") o, si no
	// se puede restar (primera ronda, reinicio, vuelta dudosa), del promedio de 5 min del equipo (Source "5min").
	// Source "" = sin dato.
	InBps, OutBps         float64
	Source                string
	InUtilPct, OutUtilPct float64 // 0 si no se conoce el BW
	// Diferencias contra la ronda anterior; solo valen con DeltaOK.
	DeltaOK                          bool
	InErrors, OutErrors, CRC, Resets int64
	InDrops, OutDrops                int64
	Reboot                           bool // el equipo se reinició desde la ronda anterior (por su uptime)
}

type IfSeries struct {
	Name, Description string
	BWKbit            int64
	PeakUtilPct       float64
	Points            []IfPoint
}

type Reboot struct {
	Round int
	At    time.Time
}

type Device struct {
	Address, Hostname string
	Rounds            int
	CPU               []CPUPoint
	Memory            []MemSeries
	Interfaces        []IfSeries
	IfaceTotal        int // interfaces con datos, antes del tope
	Reboots           []Reboot
	Truncated         bool
	Warnings          []string
	WarnT             []i18n.Text // los Warnings como texto de catálogo, en paralelo
}

type Result struct {
	Devices  []Device
	Warnings []string
	WarnT    []i18n.Text // los Warnings como texto de catálogo, en paralelo
}

// Localize da el resultado con los avisos (los suyos y los de cada equipo) en el idioma dado; con es, tal cual.
func (r Result) Localize(loc string) Result {
	if loc != i18n.En {
		return r
	}
	r.Warnings = i18n.Notes(loc, r.Warnings, r.WarnT)
	r.Devices = append([]Device(nil), r.Devices...)
	for i := range r.Devices {
		r.Devices[i].Warnings = i18n.Notes(loc, r.Devices[i].Warnings, r.Devices[i].WarnT)
	}
	return r
}

// Build lee la carpeta de salida de un trabajo de Patrol y arma las series de cada equipo.
func Build(dir string, o Options) (Result, error) {
	devs, err := listDevices(dir)
	if err != nil {
		return Result{}, fmt.Errorf("metrics: %w", err)
	}
	if o.MaxPoints <= 0 {
		o.MaxPoints = DefaultMaxPoints
	}
	o.MaxPoints = min(o.MaxPoints, MaxPoints)
	if o.MaxIfaces <= 0 {
		o.MaxIfaces = DefaultMaxIfaces
	}
	o.MaxIfaces = min(o.MaxIfaces, MaxIfaces)
	var res Result
	for _, dd := range devs {
		if !dd.matches(o.Device) { // se filtra antes de leer: un equipo ajeno no cuesta nada
			continue
		}
		if r, ok := loadDevice(dir, dd, metricsWanted(), parseMetric, false); ok {
			res.Devices = append(res.Devices, buildDevice(r, o))
		}
	}
	if o.Device != "" && len(res.Devices) == 0 {
		i18n.Note(&res.Warnings, &res.WarnT, "metrics.warn.no_device", "device", o.Device)
	}
	// interfaces pedidas que ningún equipo tiene
	for _, want := range o.Ifaces {
		w := normIf(want)
		found := false
		for _, d := range res.Devices {
			for _, s := range d.Interfaces {
				found = found || strings.EqualFold(s.Name, w)
			}
		}
		if !found && len(res.Devices) > 0 {
			i18n.Note(&res.Warnings, &res.WarnT, "metrics.warn.no_iface", "iface", w)
		}
	}
	return res, nil
}

func normIf(s string) string { return iosxe.ShortIf(strings.TrimSpace(s)) }

func buildDevice(r rawDevice, o Options) Device {
	d := Device{Address: r.IP, Hostname: r.Host}
	rounds := map[int]bool{}
	for _, s := range r.Secs {
		rounds[s.Round] = true
	}
	d.Rounds = len(rounds)
	trunc := func(n int) int { // cuántos puntos sobran al principio
		if n > o.MaxPoints {
			d.Truncated = true
			return n - o.MaxPoints
		}
		return 0
	}
	d.Warnings, d.WarnT = append(d.Warnings, r.Warnings...), append(d.WarnT, r.WarnT...)
	warn := func(key string, kv ...any) { i18n.Note(&d.Warnings, &d.WarnT, key, kv...) }

	// ---- CPU ----
	if cmd := present(r.Secs, cmdCPU); cmd == "" {
		warn("metrics.warn.missing_cmd", "cmd", strings.Join(cmdCPU, " o "), "cmd_en", strings.Join(cmdCPU, " or "))
	} else {
		bad := 0
		for _, s := range r.Secs {
			if !contains(cmdCPU, s.Cmd) {
				continue
			}
			if c, ok := s.Val.(iosxe.CPU); ok && s.OK {
				d.CPU = append(d.CPU, CPUPoint{s.Round, s.At, c.FiveSec, c.OneMin, c.FiveMin})
			} else {
				bad++
			}
		}
		if bad > 0 {
			warn("metrics.warn.unreadable", "cmd", cmd, "n", bad)
		}
		d.CPU = d.CPU[trunc(len(d.CPU)):]
	}

	// ---- memoria ----
	if cmd := present(r.Secs, cmdMem); cmd == "" {
		warn("metrics.warn.missing_cmd", "cmd", strings.Join(cmdMem, " o "), "cmd_en", strings.Join(cmdMem, " or "))
	} else {
		bad := 0
		idx := map[string]int{}
		for _, s := range r.Secs {
			if !contains(cmdMem, s.Cmd) {
				continue
			}
			pools, ok := s.Val.([]iosxe.MemPool)
			if !ok || !s.OK {
				bad++
				continue
			}
			for _, p := range pools {
				i, seen := idx[p.Name]
				if !seen {
					i = len(d.Memory)
					idx[p.Name] = i
					d.Memory = append(d.Memory, MemSeries{Pool: p.Name})
				}
				d.Memory[i].Points = append(d.Memory[i].Points, MemPoint{s.Round, s.At, p.Used, p.Free, p.Total})
			}
		}
		if bad > 0 {
			warn("metrics.warn.unreadable", "cmd", cmd, "n", bad)
		}
		for i := range d.Memory {
			d.Memory[i].Points = d.Memory[i].Points[trunc(len(d.Memory[i].Points)):]
		}
	}

	// ---- reinicios (por la hora de arranque que sale de show version) ----
	boots := bootTimes(r.Secs)
	d.Reboots = rebootsOf(boots)
	rebootAt := map[int]bool{}
	for _, b := range d.Reboots {
		rebootAt[b.Round] = true
	}

	// ---- interfaces ----
	if !hasCmd(r.Secs, cmdIfaces) {
		warn("metrics.warn.missing_cmd", "cmd", cmdIfaces, "cmd_en", cmdIfaces)
	} else {
		bad := 0
		series := map[string]*IfSeries{}
		var order []string
		last := map[string]iosxe.Iface{}
		lastAt := map[string]time.Time{}
		for _, s := range r.Secs {
			if s.Cmd != cmdIfaces {
				continue
			}
			ifs, ok := s.Val.([]iosxe.Iface)
			if !ok || !s.OK {
				bad++
				continue
			}
			for _, in := range ifs {
				ser := series[in.Name]
				if ser == nil {
					ser = &IfSeries{Name: in.Name}
					series[in.Name] = ser
					order = append(order, in.Name)
				}
				if in.Description != "" {
					ser.Description = in.Description
				}
				if in.BWKbit > 0 {
					ser.BWKbit = in.BWKbit
				}
				p := IfPoint{Round: s.Round, At: s.At}
				prev, hadPrev := last[in.Name]
				p.Reboot = hadPrev && rebootAt[s.Round]
				ratePoint(&p, in, prev, lastAt[in.Name], hadPrev, ser.BWKbit)
				if in.HasBytes {
					last[in.Name], lastAt[in.Name] = in, s.At
				}
				ser.Points = append(ser.Points, p)
			}
		}
		if bad > 0 {
			warn("metrics.warn.unreadable", "cmd", cmdIfaces, "n", bad)
		}
		d.IfaceTotal = len(order)
		all := make([]*IfSeries, 0, len(order))
		for _, n := range order {
			s := series[n]
			for _, p := range s.Points {
				s.PeakUtilPct = max(s.PeakUtilPct, p.InUtilPct, p.OutUtilPct)
			}
			all = append(all, s)
		}
		for _, s := range pick(all, o) {
			s.Points = s.Points[trunc(len(s.Points)):]
			d.Interfaces = append(d.Interfaces, *s)
		}
		if d.IfaceTotal > 0 && len(d.Interfaces) < d.IfaceTotal && len(o.Ifaces) == 0 {
			warn("metrics.warn.top_ifaces", "shown", len(d.Interfaces), "total", d.IfaceTotal)
		}
	}
	return d
}

func peakBps(s *IfSeries) float64 {
	var m float64
	for _, p := range s.Points {
		m = max(m, p.InBps, p.OutBps)
	}
	return m
}

// pick aplica las interfaces pedidas o el top N por utilización pico (desempate: tráfico pico, nombre).
func pick(all []*IfSeries, o Options) []*IfSeries {
	if len(o.Ifaces) > 0 {
		want := map[string]bool{}
		for _, w := range o.Ifaces {
			want[strings.ToLower(normIf(w))] = true
		}
		var out []*IfSeries
		for _, s := range all {
			if want[strings.ToLower(s.Name)] {
				out = append(out, s)
			}
		}
		return out
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.PeakUtilPct != b.PeakUtilPct {
			return a.PeakUtilPct > b.PeakUtilPct
		}
		if pa, pb := peakBps(a), peakBps(b); pa != pb {
			return pa > pb
		}
		return a.Name < b.Name
	})
	return all[:min(len(all), o.MaxIfaces)]
}

// ratePoint llena la tasa, la utilización y las diferencias de p contra la lectura anterior de la interfaz.
func ratePoint(p *IfPoint, cur, prev iosxe.Iface, prevAt time.Time, hadPrev bool, bwKbit int64) {
	fallback := func() { // promedio de 5 min del equipo
		if cur.HasRate {
			p.InBps, p.OutBps, p.Source = float64(cur.InRateBps), float64(cur.OutRateBps), "5min"
		}
	}
	defer func() {
		if bwKbit > 0 {
			p.InUtilPct = p.InBps * 100 / (float64(bwKbit) * 1000)
			p.OutUtilPct = p.OutBps * 100 / (float64(bwKbit) * 1000)
		}
	}()
	if !hadPrev || !cur.HasBytes || p.Reboot {
		fallback()
		return
	}
	dt := p.At.Sub(prevAt).Seconds()
	if cur.HasClear && cur.ClearAgo.Seconds() < dt { // clear counters desde la lectura anterior: otro tipo de reinicio
		fallback()
		return
	}
	in, okIn := octetRate(prev.InBytes, cur.InBytes, dt, bwKbit)
	out, okOut := octetRate(prev.OutBytes, cur.OutBytes, dt, bwKbit)
	if okIn && okOut {
		p.InBps, p.OutBps, p.Source = in, out, "counters"
	} else {
		fallback()
	}
	var ok [6]bool
	p.InErrors, ok[0] = counterDelta(prev.InErrors, cur.InErrors)
	p.OutErrors, ok[1] = counterDelta(prev.OutErrors, cur.OutErrors)
	p.CRC, ok[2] = counterDelta(prev.CRC, cur.CRC)
	p.Resets, ok[3] = counterDelta(prev.Resets, cur.Resets)
	p.InDrops, ok[4] = counterDelta(prev.InDrops, cur.InDrops)
	p.OutDrops, ok[5] = counterDelta(prev.OutDrops, cur.OutDrops)
	p.DeltaOK = ok[0] && ok[1] && ok[2] && ok[3] && ok[4] && ok[5]
	if !p.DeltaOK { // un contador que bajó: no se muestran diferencias a medias
		p.InErrors, p.OutErrors, p.CRC, p.Resets, p.InDrops, p.OutDrops = 0, 0, 0, 0, 0, 0
	}
}

type boot struct {
	Round int
	At    time.Time // hora de arranque estimada: hora de la salida menos el uptime
}

func bootTimes(secs []section) []boot {
	var out []boot
	seen := map[int]bool{}
	for _, s := range secs {
		if s.Cmd != cmdVersion || seen[s.Round] {
			continue
		}
		if v, ok := s.Val.(iosxe.Version); ok && s.OK && v.UptimeKnown {
			seen[s.Round] = true
			out = append(out, boot{s.Round, s.At.Add(-v.Uptime)})
		}
	}
	return out
}

// rebootsOf marca la ronda donde la hora de arranque se movió más allá de la precisión del uptime.
func rebootsOf(b []boot) []Reboot {
	var out []Reboot
	for i := 1; i < len(b); i++ {
		if b[i].At.Sub(b[i-1].At) > rebootSlack {
			out = append(out, Reboot{b[i].Round, b[i].At})
		}
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func hasCmd(secs []section, cmd string) bool { return present(secs, []string{cmd}) != "" }

// present devuelve el primer comando de cmds que tenga alguna sección.
func present(secs []section, cmds []string) string {
	for _, c := range cmds {
		for _, s := range secs {
			if s.Cmd == c {
				return c
			}
		}
	}
	return ""
}
