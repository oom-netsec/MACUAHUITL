package metrics

import (
	"math"
	"testing"
)

func TestOctetRate(t *testing.T) {
	const gig = 1_000_000 // BW en Kbit/s
	cases := []struct {
		name      string
		prev, cur int64
		dt        float64
		bw        int64
		want      float64
		ok        bool
	}{
		{"normal", 1000, 1000 + 37_500_000, 300, gig, 1_000_000, true}, // 37,5 MB en 300 s = 1 Mb/s
		{"sin trafico", 5000, 5000, 60, gig, 0, true},
		{"dt cero", 1, 2, 0, gig, 0, false},
		{"dt negativo", 1, 2, -5, gig, 0, false},
		{"da la vuelta a 32 bits", 4_294_000_000, 5_000_000, 10, gig, (float64(1<<32-4_294_000_000+5_000_000) * 8) / 10, true},
		{"reinicio de 64 bits (baja desde mas de 2^32)", 9_000_000_000, 100, 300, gig, 0, false},
		{"baja desde poco: reinicio, no vuelta", 1_000, 10, 300, gig, 0, false},
		{"vuelta con tasa imposible", 4_294_000_000, 4_000_000_000 - 1_000_000, 10, gig, 0, false}, // 4 GB en 10 s a 1 Gb/s
		{"supera la velocidad del puerto", 0, 2_000_000_000, 10, gig, 0, false},
		{"mas de una vuelta posible", 4_294_000_000, 1000, 40, gig, 0, false}, // 40 s ≥ 2^32*8/1Gb/s = 34 s
		{"sin BW no se aceptan vueltas (puede ser un clear counters)", 4_294_000_000, 1000, 40, 0, 0, false},
		{"sin BW: baja desde 2^31 a 2^32", 3_000_000_000, 5000, 300, 0, 0, false},
		{"sin BW: baja desde poco es reinicio", 1_000, 10, 300, 0, 0, false},
		{"sin BW: baja desde mas de 2^32 es reinicio", 9_000_000_000, 100, 300, 0, 0, false},
		{"sin BW: dt cero", 1, 2, 0, 0, 0, false},
		{"sin BW el tope no aplica", 0, 1_000_000_000, 10, 0, 800_000_000, true},
	}
	for _, c := range cases {
		got, ok := octetRate(c.prev, c.cur, c.dt, c.bw)
		if ok != c.ok || (ok && math.Abs(got-c.want) > 0.5) {
			t.Errorf("%s: octetRate = %v, %v; quería %v, %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestCounterDelta(t *testing.T) {
	if d, ok := counterDelta(5, 12); !ok || d != 7 {
		t.Errorf("sube: %d %v", d, ok)
	}
	if d, ok := counterDelta(5, 5); !ok || d != 0 {
		t.Errorf("igual: %d %v", d, ok)
	}
	if _, ok := counterDelta(12, 5); ok {
		t.Error("un contador que baja es un reinicio, no una diferencia negativa")
	}
}
