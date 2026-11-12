package logintel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/msgkb"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// FlapOptions: flapping = Count transiciones de una interfaz dentro de Window (por defecto 3 en 60 s).
type FlapOptions struct {
	Count  int
	Window time.Duration
}

func (o FlapOptions) norm() FlapOptions {
	if o.Count <= 0 {
		o.Count = 3
	}
	if o.Window <= 0 {
		o.Window = 60 * time.Second
	}
	return o
}

const maxSequence = 12

// Flap es una interfaz que cambia de estado demasiado seguido.
type Flap struct {
	Host      string       `json:"host,omitempty"`
	Interface string       `json:"interface"`
	Layer     string       `json:"layer"`    // link (%LINK-3-UPDOWN) o lineproto (%LINEPROTO-5-UPDOWN)
	Total     int          `json:"total"`    // transiciones vistas en todo el log
	Peak      int          `json:"peak"`     // más transiciones dentro de una ventana
	Episodes  int          `json:"episodes"` // veces que se llegó al umbral
	First     time.Time    `json:"first,omitzero"`
	Last      time.Time    `json:"last,omitzero"`
	Sequence  string       `json:"sequence"`           // primeros estados: "down up down up"
	NoTime    bool         `json:"no_time,omitempty"`  // los mensajes no traen hora: posible flapping, sin ventana
	Mnemonic  string       `json:"mnemonic,omitempty"` // llave de la ficha en FlapReport.KB
	KB        *msgkb.Entry `json:"-"`
}

// FlapReport reúne las interfaces con flapping y los totales.
type FlapReport struct {
	Flaps       []Flap                 `json:"flaps"`
	Interfaces  int                    `json:"interfaces"`  // interfaces con al menos una transición
	Transitions int                    `json:"transitions"` // transiciones contadas (una capa por interfaz)
	Count       int                    `json:"count"`
	Window      string                 `json:"window"`
	Warnings    []string               `json:"warnings,omitempty"`
	KB          map[string]msgkb.Entry `json:"kb,omitempty"` // fichas por mnemónico, una vez
}

var (
	linkRe  = regexp.MustCompile(`%LINK-3-UPDOWN: Interface ([^\s,]+), changed state to (up|down)\b`)
	protoRe = regexp.MustCompile(`%LINEPROTO-5-UPDOWN: Line protocol on Interface ([^\s,]+), changed state to (up|down)\b`)
)

type trans struct {
	at    time.Time
	state string
}

type ifKey struct{ host, ifc string }

// Flaps busca interfaces con Count transiciones dentro de Window, con la precisión de
// milisegundos de la marca: una caída de milisegundos cuenta. Cuando una interfaz tiene
// %LINK-3-UPDOWN se cuenta solo esa capa (un mismo corte genera también %LINEPROTO); si solo
// tiene %LINEPROTO (VLAN, loopback, túneles) se cuenta esa. Las transiciones
// administrativas (%LINK-5-CHANGED) no cuentan: alguien las pidió.
func Flaps(es []Entry, o FlapOptions) FlapReport {
	o = o.norm()
	rep := FlapReport{Flaps: []Flap{}, Count: o.Count, Window: o.Window.String()}
	link, proto := map[ifKey][]trans{}, map[ifKey][]trans{}
	for _, e := range es {
		for _, c := range []struct {
			re *regexp.Regexp
			m  map[ifKey][]trans
		}{{linkRe, link}, {protoRe, proto}} {
			if m := c.re.FindStringSubmatch(e.Text); m != nil {
				k := ifKey{e.Host, iosxe.ShortIf(m[1])}
				c.m[k] = append(c.m[k], trans{e.At, m[2]})
			}
		}
	}
	kb, _ := msgkb.Default()
	noTime := 0
	each := func(m map[ifKey][]trans, layer string, skip map[ifKey][]trans) {
		for k, ts := range m {
			if _, dup := skip[k]; dup {
				continue
			}
			rep.Interfaces++
			rep.Transitions += len(ts)
			f := Flap{Host: k.host, Interface: k.ifc, Layer: layer, Total: len(ts)}
			var times []time.Time
			var seq []string
			for _, t := range ts {
				if len(seq) < maxSequence {
					seq = append(seq, t.state)
				}
				if !t.at.IsZero() {
					times = append(times, t.at)
				}
			}
			f.Sequence = strings.Join(seq, " ")
			if len(times) == 0 {
				if len(ts) < o.Count {
					continue
				}
				f.NoTime = true
				noTime += len(ts)
			} else {
				sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
				f.First, f.Last = times[0], times[len(times)-1]
				f.Peak, f.Episodes = peaks(times, o.Window, o.Count)
				if f.Episodes == 0 {
					continue
				}
			}
			if kb != nil {
				id := "%LINK-3-UPDOWN"
				if layer == "lineproto" {
					id = "%LINEPROTO-5-UPDOWN"
				}
				if e, ok := kb.Lookup(id); ok {
					f.KB, f.Mnemonic = &e, id
					if rep.KB == nil {
						rep.KB = map[string]msgkb.Entry{}
					}
					rep.KB[id] = e
				}
			}
			rep.Flaps = append(rep.Flaps, f)
		}
	}
	each(link, "link", nil)
	each(proto, "lineproto", link)
	sort.Slice(rep.Flaps, func(i, j int) bool {
		a, b := rep.Flaps[i], rep.Flaps[j]
		switch {
		case a.Peak != b.Peak:
			return a.Peak > b.Peak
		case a.Total != b.Total:
			return a.Total > b.Total
		case a.Host != b.Host:
			return a.Host < b.Host
		}
		return a.Interface < b.Interface
	})
	if noTime > 0 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("hay interfaces con %d transición(es) sin hora: son posible flapping, pero sin hora no se mide la ventana (activa service timestamps log datetime msec)", noTime))
	}
	return rep
}

// peaks recorre tiempos ordenados: devuelve el máximo de eventos dentro de una ventana y
// cuántos episodios hubo. Histéresis: un episodio nuevo solo abre si pasó una ventana completa
// desde la última vez que se estuvo en el umbral; si no, un mensaje periódico cuyo conteo
// oscila entre n-1 y n (variación de milisegundos) contaría un episodio por cada oscilación.
func peaks(times []time.Time, window time.Duration, n int) (peak, episodes int) {
	lo := 0
	var lastHit time.Time
	for j, t := range times {
		for t.Sub(times[lo]) > window {
			lo++
		}
		c := j - lo + 1
		peak = max(peak, c)
		if c >= n {
			if episodes == 0 || t.Sub(lastHit) > window {
				episodes++
			}
			lastHit = t
		}
	}
	return peak, episodes
}

// Text arma el informe legible.
func (r FlapReport) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d interfaz(ces) con transiciones, %d transición(es). Flapping: %d o más en %s.\n", r.Interfaces, r.Transitions, r.Count, r.Window)
	if len(r.Flaps) == 0 {
		b.WriteString("Ninguna interfaz con flapping.\n")
	}
	for _, f := range r.Flaps {
		host := f.Host
		if host == "" {
			host = "-"
		}
		if f.NoTime {
			fmt.Fprintf(&b, "\n[POSIBLE, SIN HORA] %s %s: %d transiciones (%s)\n", host, f.Interface, f.Total, f.Sequence)
		} else {
			fmt.Fprintf(&b, "\n[FLAPPING] %s %s: %d transiciones en una ventana (pico), %d en total, de %s a %s (%s)\n", host, f.Interface, f.Peak, f.Total, f.First.UTC().Format(time.RFC3339Nano), f.Last.UTC().Format(time.RFC3339Nano), f.Sequence)
		}
		if f.KB != nil {
			fmt.Fprintf(&b, "    %s Causa probable: %s Acción: %s\n", f.KB.ID, f.KB.Cause, f.KB.Action)
		}
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(&b, "\nAviso: %s\n", w)
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- saltos de contadores entre rondas de Patrol ----

// CounterSample es el valor de los contadores de una interfaz en una ronda (de show interfaces).
type CounterSample struct {
	Host      string
	Round     int
	At        time.Time
	Interface string
	Counters  map[string]int64 // "interface resets", "lost carrier", "no carrier", "carrier transitions"
}

// CounterJump es un contador que subió demasiado entre dos rondas consecutivas.
type CounterJump struct {
	Host      string  `json:"host"`
	Interface string  `json:"interface"`
	Counter   string  `json:"counter"`
	FromRound int     `json:"from_round"`
	ToRound   int     `json:"to_round"`
	From      int64   `json:"from"`
	To        int64   `json:"to"`
	Delta     int64   `json:"delta"`
	PerHour   float64 `json:"per_hour,omitempty"` // 0 si las rondas no traen hora
}

// CounterJumps compara cada ronda con la anterior del mismo equipo e interfaz y devuelve los
// contadores que subieron minDelta o más (por defecto 3). Un contador que baja se borró
// (clear counters o recarga): esa pareja no cuenta, y la siguiente se compara con el valor nuevo.
func CounterJumps(ss []CounterSample, minDelta int64) []CounterJump {
	if minDelta <= 0 {
		minDelta = 3
	}
	by := map[ifKey][]CounterSample{}
	for _, s := range ss {
		k := ifKey{s.Host, s.Interface}
		by[k] = append(by[k], s)
	}
	out := []CounterJump{}
	for k, list := range by {
		sort.Slice(list, func(i, j int) bool { return list[i].Round < list[j].Round })
		for i := 1; i < len(list); i++ {
			a, b := list[i-1], list[i]
			for name, to := range b.Counters {
				from, ok := a.Counters[name]
				if !ok || to-from < minDelta { // si bajó, el contador se borró y la resta es negativa
					continue
				}
				j := CounterJump{Host: k.host, Interface: k.ifc, Counter: name, FromRound: a.Round, ToRound: b.Round, From: from, To: to, Delta: to - from}
				if d := b.At.Sub(a.At); !a.At.IsZero() && !b.At.IsZero() && d > 0 {
					j.PerHour = float64(j.Delta) / d.Hours()
				}
				out = append(out, j)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.Host != b.Host:
			return a.Host < b.Host
		case a.Interface != b.Interface:
			return a.Interface < b.Interface
		case a.ToRound != b.ToRound:
			return a.ToRound < b.ToRound
		}
		return a.Counter < b.Counter
	})
	return out
}

// JumpsText arma el bloque legible de los saltos de contadores.
func JumpsText(js []CounterJump) string {
	if len(js) == 0 {
		return "Ningún contador de interfaz saltó entre rondas."
	}
	var b strings.Builder
	for _, j := range js {
		fmt.Fprintf(&b, "[SALTO] %s %s: %s subió de %d a %d (+%d) entre las rondas %d y %d", j.Host, j.Interface, j.Counter, j.From, j.To, j.Delta, j.FromRound, j.ToRound)
		if j.PerHour > 0 {
			fmt.Fprintf(&b, " (%.1f por hora)", j.PerHour)
		}
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}
