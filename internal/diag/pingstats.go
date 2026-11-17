package diag

import (
	"math"
	"regexp"
	"strconv"
)

// PingSummary es el resumen que el núcleo calcula de las respuestas, igual en Linux y en Windows.
type PingSummary struct {
	Sent, Received              int64
	LossPct                     float64
	MinMs, AvgMs, MaxMs, MdevMs float64
}

// PingStats lleva la cuenta a partir de las líneas de iputils (win=false) o de ping.exe (win=true, es/en).
// No es seguro entre goroutines: el Runner lo usa bajo su candado.
type PingStats struct {
	win            bool
	sent, received int64
	maxSeq, final  int64 // iputils: icmp_seq más alto y «N packets transmitted»
	times          []float64
}

func NewPingStats(win bool) *PingStats { return &PingStats{win: win} }

var (
	reLinuxEcho  = regexp.MustCompile(`^\d+ bytes from .*icmp_seq=(\d+) .*time=([\d.]+) ms( \(DUP!\))?`)
	reLinuxSeq   = regexp.MustCompile(`icmp_seq=(\d+)`) // «no answer yet», «Destination Host Unreachable»…
	reLinuxFinal = regexp.MustCompile(`^(\d+) packets transmitted`)
	reWinEcho    = regexp.MustCompile(`(?i)^(?:Reply from|Respuesta desde) \S+: bytes=\d+ (?:time|tiempo)([=<])(\d+)ms`)
	reWinNoEcho  = regexp.MustCompile(`(?i)^(?:Request timed out|Tiempo de espera agotado|(?:Reply from|Respuesta desde) \S+: |PING: transmit failed|General failure|Error general)`)
)

// Feed cuenta una línea de salida y devuelve cuántos envíos lleva (para el tope).
// Linux: enviados = el icmp_seq más alto visto (o el «transmitted» final si es mayor), porque iputils no
// imprime los timeouts; Windows: cada eco con respuesta y cada «sin respuesta» o error.
func (p *PingStats) Feed(line string) int64 {
	if p.win {
		if m := reWinEcho.FindStringSubmatch(line); m != nil {
			ms, _ := strconv.ParseFloat(m[2], 64)
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
		p.seq(m[1])
		if m[3] == "" {
			ms, _ := strconv.ParseFloat(m[2], 64)
			p.received++
			p.times = append(p.times, ms)
		}
	} else if m := reLinuxFinal.FindStringSubmatch(line); m != nil {
		p.final, _ = strconv.ParseInt(m[1], 10, 64)
	} else if m := reLinuxSeq.FindStringSubmatch(line); m != nil {
		p.seq(m[1])
	}
	return max(p.maxSeq, p.final)
}

func (p *PingStats) seq(s string) {
	if n, _ := strconv.ParseInt(s, 10, 64); n > p.maxSeq {
		p.maxSeq = n
	}
}

// Summary calcula el resumen; mdev es la desviación media absoluta respecto del promedio.
func (p *PingStats) Summary() PingSummary {
	s := PingSummary{Sent: p.sent, Received: p.received}
	if !p.win {
		s.Sent = max(p.maxSeq, p.final)
	}
	s.Received = min(s.Received, s.Sent)
	if s.Sent > 0 {
		s.LossPct = float64(s.Sent-s.Received) / float64(s.Sent) * 100
	}
	if len(p.times) == 0 {
		return s
	}
	s.MinMs, s.MaxMs = math.Inf(1), math.Inf(-1)
	var sum float64
	for _, t := range p.times {
		s.MinMs, s.MaxMs, sum = min(s.MinMs, t), max(s.MaxMs, t), sum+t
	}
	s.AvgMs = sum / float64(len(p.times))
	for _, t := range p.times {
		s.MdevMs += math.Abs(t - s.AvgMs)
	}
	s.MdevMs /= float64(len(p.times))
	return s
}
