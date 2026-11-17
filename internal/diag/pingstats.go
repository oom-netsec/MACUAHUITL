package diag

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

// PingSummary es el resumen que el núcleo calcula de las respuestas, igual en Linux y en Windows.
type PingSummary struct {
	Sent, Received              int64
	LossPct                     float64
	MinMs, AvgMs, MaxMs, MdevMs float64
}

// PingStats lleva la cuenta a partir de las líneas de iputils (win=false) o de ping.exe (win=true, es/en).
// No es seguro entre goroutines: el Runner lo usa bajo su candado.
//
// Un «Destination host unreachable» de Windows cuenta como enviado sin respuesta, igual que el nerrors de
// iputils, aunque el resumen de ping.exe lo cuente como recibido.
type PingStats struct {
	win            bool
	sent, received int64
	maxSeq, final  int64 // iputils: icmp_seq más alto (con las vueltas de 65535) y «N packets transmitted»
	lastRaw, epoch int64
	times          []float64 // en iputils incluye los DUP, como tsum de iputils
	rtt            *[4]float64
	frag           bool // el sistema avisó que hacía falta fragmentar con DF
}

func NewPingStats(win bool) *PingStats { return &PingStats{win: win} }

const (
	maxSeqSane = 1e9 // un icmp_seq mayor es basura
	maxMsSane  = 1e7 // un tiempo mayor (casi 3 h) es basura
)

var (
	reLinuxEcho  = regexp.MustCompile(`^\d+ bytes from .*icmp_seq=(\d+)\b(.*)$`)
	reLinuxTime  = regexp.MustCompile(`\btime=([\d.]+) ms`)
	reLinuxSeq   = regexp.MustCompile(`icmp_seq=(\d+)`) // «no answer yet», «Destination Host Unreachable»…
	reLinuxFinal = regexp.MustCompile(`^(\d+) packets transmitted`)
	reLinuxRTT   = regexp.MustCompile(`^(?:rtt|round-trip) min/avg/max/(?:mdev|stddev) = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+) ms`)
	reWinEcho    = regexp.MustCompile(`(?i)^(?:Reply from|Respuesta desde) \S+: (?:bytes=\d+ )?(?:time|tiempo)([=<])(\d+)ms?`)
	reFrag       = regexp.MustCompile(`(?i)message too long|frag needed|needs to be fragmented|es necesario fragmentar`)
	reWinNoEcho  = regexp.MustCompile(`(?i)^(?:Request timed out|Packet needs to be fragmented|Es necesario fragmentar|Tiempo de espera agotado|(?:Reply from|Respuesta desde) \S+: |PING: transmit failed|General failure|Error general)`)
)

// num convierte un número del texto; falla si no es finito o pasa de max.
func num(s string, max float64) (float64, bool) {
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) && v <= max
}

// Feed cuenta una línea de salida y devuelve cuántos envíos lleva (para el tope).
// Linux: enviados = el icmp_seq más alto visto (o el «transmitted» final si es mayor), porque iputils no
// imprime los timeouts; Windows: cada eco con respuesta y cada «sin respuesta» o error.
func (p *PingStats) Feed(line string) int64 {
	if reFrag.MatchString(line) {
		p.frag = true
	}
	if p.win {
		if m := reWinEcho.FindStringSubmatch(line); m != nil {
			ms, ok := num(m[2], maxMsSane)
			if !ok {
				return p.sent
			}
			if m[1] == "<" {
				ms = 0 // «<1ms»
			}
			p.sent++
			p.received++
			p.times = append(p.times, ms)
		} else if reWinNoEcho.MatchString(line) {
			p.sent++
		}
		return p.sent
	}
	if m := reLinuxEcho.FindStringSubmatch(line); m != nil {
		var ms float64
		hasTime := false
		if t := reLinuxTime.FindStringSubmatch(m[2]); t != nil { // con size de 0 a 15 no hay time=
			if ms, hasTime = num(t[1], maxMsSane); !hasTime {
				return max(p.maxSeq, p.final)
			}
		}
		if !p.seq(m[1]) {
			return max(p.maxSeq, p.final)
		}
		bad := strings.Contains(m[2], "(BAD CHECKSUM!)")
		if hasTime && !bad {
			p.times = append(p.times, ms) // los DUP también: iputils los suma a tsum, min y max
		}
		if !bad && !strings.Contains(m[2], "(DUP!)") {
			p.received++
		}
	} else if m := reLinuxFinal.FindStringSubmatch(line); m != nil {
		if n, ok := num(m[1], maxSeqSane); ok {
			p.final = int64(n)
		}
	} else if m := reLinuxRTT.FindStringSubmatch(line); m != nil {
		var r [4]float64
		for i := range r {
			var ok bool
			if r[i], ok = num(m[i+1], maxMsSane); !ok {
				return max(p.maxSeq, p.final)
			}
		}
		p.rtt = &r
	} else if m := reLinuxSeq.FindStringSubmatch(line); m != nil {
		p.seq(m[1])
	}
	return max(p.maxSeq, p.final)
}

// Frag dice si se vio el aviso de fragmentación con DF (iputils «Message too long»/«Frag needed», ping.exe «needs to be fragmented»).
func (p *PingStats) Frag() bool { return p.frag }

// Add suma el resultado de otra corrida (el barrido): enviados, recibidos y tiempos. Los icmp_seq de cada corrida
// empiezan en 1, por eso se acumulan los enviados ya resumidos y no el máximo.
func (p *PingStats) Add(o *PingStats) {
	s := o.Summary()
	p.sent += s.Sent
	p.final += s.Sent
	p.received += s.Received
	p.times = append(p.times, o.times...)
	p.frag = p.frag || o.frag
}

// seq registra un icmp_seq (16 bits: da la vuelta en 65535) y dice si el número es creíble.
func (p *PingStats) seq(s string) bool {
	f, ok := num(s, maxSeqSane)
	if !ok {
		return false
	}
	n := int64(f)
	v := n + p.epoch
	switch {
	case n < p.lastRaw-32768: // dio la vuelta
		p.epoch += 65536
		p.lastRaw, v = n, n+p.epoch
	case p.epoch > 0 && n > p.lastRaw+32768: // rezagado de antes de la vuelta
		v -= 65536
	default:
		p.lastRaw = n
	}
	p.maxSeq = max(p.maxSeq, v)
	return true
}

// Summary calcula el resumen. mdev es la desviación estándar poblacional, como iputils. En Linux, si salió
// la línea «rtt min/avg/max/mdev», se usan sus valores para que coincidan al dígito con lo que ve el usuario.
func (p *PingStats) Summary() PingSummary {
	s := PingSummary{Sent: p.sent, Received: p.received}
	if !p.win {
		s.Sent = max(p.maxSeq, p.final)
	}
	s.Received = min(s.Received, s.Sent)
	if s.Sent > 0 {
		s.LossPct = float64(s.Sent-s.Received) / float64(s.Sent) * 100
	}
	if p.rtt != nil && !p.win {
		s.MinMs, s.AvgMs, s.MaxMs, s.MdevMs = p.rtt[0], p.rtt[1], p.rtt[2], p.rtt[3]
		return s
	}
	if len(p.times) == 0 {
		return s
	}
	s.MinMs, s.MaxMs = math.Inf(1), math.Inf(-1)
	var sum float64
	for _, t := range p.times {
		s.MinMs, s.MaxMs, sum = min(s.MinMs, t), max(s.MaxMs, t), sum+t
	}
	n := float64(len(p.times))
	s.AvgMs = sum / n
	for _, t := range p.times {
		s.MdevMs += (t - s.AvgMs) * (t - s.AvgMs)
	}
	s.MdevMs = math.Sqrt(s.MdevMs / n)
	return s
}
