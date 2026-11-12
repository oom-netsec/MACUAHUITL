package logintel

import (
	"sort"
	"testing"
	"time"
)

const MiB = 1 << 20

func samples(host string, series map[string][]int64) []MemSample {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	n := 0
	var names []string
	for name, s := range series {
		n = max(n, len(s))
		names = append(names, name)
	}
	sort.Strings(names) // el PID de cada proceso no cambia entre rondas
	var out []MemSample
	for r := 0; r < n; r++ {
		ms := MemSample{Host: host, Round: r + 1, At: t0.Add(time.Duration(r) * 30 * time.Minute)}
		for i, name := range names {
			if s := series[name]; r < len(s) && s[r] >= 0 {
				ms.Procs = append(ms.Procs, Proc{PID: i + 1, Name: name, Holding: s[r]})
			}
		}
		out = append(out, ms)
	}
	return out
}

func TestMemLeaksCrecimientoMonotono(t *testing.T) {
	ss := samples("sw", map[string][]int64{
		"BGP Router":   {10 * MiB, 11 * MiB, 13 * MiB, 14 * MiB}, // fuga: +4 MiB en 3 rondas
		"IP Input":     {5 * MiB, 5 * MiB, 5 * MiB, 5 * MiB},     // estable
		"CDP Protocol": {1 * MiB, 3 * MiB, 2 * MiB, 4 * MiB},     // sube y baja: no es monótono
		"Pequeño":      {100, 200, 300, 400},                     // monótono pero ínfimo
		"*Dead*":       {1 * MiB, 5 * MiB, 9 * MiB, 20 * MiB},    // agregado del sistema, no un proceso
	})
	rep := MemLeaks(ss, LeakOptions{})
	if len(rep.Leaks) != 1 {
		t.Fatalf("%+v", rep.Leaks)
	}
	l := rep.Leaks[0]
	if l.Process != "BGP Router" || l.Host != "sw" || l.Growth != 4*MiB || l.Rounds != 4 || l.FromRound != 1 || l.ToRound != 4 || l.PerHour != float64(4*MiB)/1.5 {
		t.Fatalf("%+v", l)
	}
	if len(l.Series) != 4 || l.Series[3] != 14*MiB {
		t.Fatalf("serie %v", l.Series)
	}
	if rep.Processes != 4 { // *Dead* no cuenta
		t.Fatalf("procesos analizados: %d", rep.Processes)
	}
}

func TestMemLeaksUmbrales(t *testing.T) {
	ss := samples("sw", map[string][]int64{"P": {10 * MiB, 10*MiB + 600*1024, 10*MiB + 1200*1024}}) // +1.17 MiB en 3 rondas
	if rep := MemLeaks(ss, LeakOptions{}); len(rep.Leaks) != 1 {
		t.Fatalf("por defecto: %+v", rep.Leaks)
	}
	if rep := MemLeaks(ss, LeakOptions{MinGrowth: 2 * MiB}); len(rep.Leaks) != 0 {
		t.Fatalf("2 MiB: %+v", rep.Leaks)
	}
	if rep := MemLeaks(ss, LeakOptions{MinRounds: 4}); len(rep.Leaks) != 0 || len(rep.Warnings) == 0 {
		t.Fatalf("4 rondas con 3 muestras: %+v", rep)
	}
	// Con dos rondas no se puede hablar de tendencia.
	if rep := MemLeaks(ss[:2], LeakOptions{}); len(rep.Leaks) != 0 || len(rep.Warnings) == 0 {
		t.Fatalf("2 rondas: %+v", rep)
	}
	// Exactamente el mínimo de crecimiento cuenta.
	ss = samples("sw", map[string][]int64{"P": {MiB, 2 * MiB, 3 * MiB}})
	if rep := MemLeaks(ss, LeakOptions{MinGrowth: 2 * MiB}); len(rep.Leaks) != 1 {
		t.Fatalf("límite exacto: %+v", rep.Leaks)
	}
}

func TestMemLeaksMesetasYReinicios(t *testing.T) {
	// Una meseta en medio es monótona si la mitad de los pasos crece.
	ss := samples("sw", map[string][]int64{"P": {1 * MiB, 3 * MiB, 3 * MiB, 5 * MiB}})
	if rep := MemLeaks(ss, LeakOptions{}); len(rep.Leaks) != 1 || rep.Leaks[0].Rounds != 4 {
		t.Fatalf("meseta: %+v", rep.Leaks)
	}
	// Justo la mitad de los pasos sube (2 de 4): todavía cuenta.
	ss = samples("sw", map[string][]int64{"P": {1 * MiB, 1 * MiB, 3 * MiB, 3 * MiB, 5 * MiB}})
	if rep := MemLeaks(ss, LeakOptions{}); len(rep.Leaks) != 1 {
		t.Fatalf("mitad exacta: %+v", rep.Leaks)
	}
	// Casi todo plano: menos de la mitad de los pasos crece.
	ss = samples("sw", map[string][]int64{"P": {1 * MiB, 1 * MiB, 1 * MiB, 1 * MiB, 5 * MiB}})
	if rep := MemLeaks(ss, LeakOptions{}); len(rep.Leaks) != 0 {
		t.Fatalf("un solo salto: %+v", rep.Leaks)
	}
	// Una recarga a mitad (la memoria cae) parte la serie: solo cuenta lo posterior.
	ss = samples("sw", map[string][]int64{"P": {50 * MiB, 60 * MiB, 1 * MiB, 3 * MiB, 5 * MiB}})
	rep := MemLeaks(ss, LeakOptions{})
	if len(rep.Leaks) != 1 || rep.Leaks[0].FromRound != 3 || rep.Leaks[0].Growth != 4*MiB || rep.Leaks[0].Rounds != 3 {
		t.Fatalf("tras la recarga: %+v", rep.Leaks)
	}
	// El proceso que ya no está en la última ronda no se reporta.
	ss = samples("sw", map[string][]int64{"P": {1 * MiB, 3 * MiB, 5 * MiB, -1}, "Q": {1, 1, 1, 1}})
	if rep := MemLeaks(ss, LeakOptions{}); len(rep.Leaks) != 0 {
		t.Fatalf("proceso ausente: %+v", rep.Leaks)
	}
}

func TestMemLeaksSeparaEquiposYPIDs(t *testing.T) {
	a := samples("sw1", map[string][]int64{"P": {1 * MiB, 3 * MiB, 5 * MiB}})
	b := samples("sw2", map[string][]int64{"P": {5 * MiB, 3 * MiB, 1 * MiB}})
	rep := MemLeaks(append(a, b...), LeakOptions{})
	if len(rep.Leaks) != 1 || rep.Leaks[0].Host != "sw1" {
		t.Fatalf("%+v", rep.Leaks)
	}
	// El mismo nombre con otro PID es otro proceso (se reinició): no se mezclan sus series.
	s1 := MemSample{Host: "h", Round: 1, Procs: []Proc{{PID: 10, Name: "P", Holding: 1 * MiB}}}
	s2 := MemSample{Host: "h", Round: 2, Procs: []Proc{{PID: 11, Name: "P", Holding: 3 * MiB}}}
	s3 := MemSample{Host: "h", Round: 3, Procs: []Proc{{PID: 12, Name: "P", Holding: 5 * MiB}}}
	if rep := MemLeaks([]MemSample{s1, s2, s3}, LeakOptions{}); len(rep.Leaks) != 0 {
		t.Fatalf("PIDs distintos: %+v", rep.Leaks)
	}
}

func TestMemLeaksOrdenaPorCrecimientoYTieneTexto(t *testing.T) {
	ss := samples("sw", map[string][]int64{"A": {1 * MiB, 3 * MiB, 5 * MiB}, "B": {1 * MiB, 11 * MiB, 21 * MiB}})
	rep := MemLeaks(ss, LeakOptions{})
	if len(rep.Leaks) != 2 || rep.Leaks[0].Process != "B" {
		t.Fatalf("%+v", rep.Leaks)
	}
	txt := rep.Text()
	for _, w := range []string{"[FUGA POSIBLE] sw B", "+20.0 MiB", "rondas 1 a 3"} {
		if !contains(txt, w) {
			t.Errorf("falta %q en:\n%s", w, txt)
		}
	}
}

func TestMemLeaksSinMuestras(t *testing.T) {
	rep := MemLeaks(nil, LeakOptions{})
	if len(rep.Leaks) != 0 || rep.Leaks == nil || len(rep.Warnings) == 0 {
		t.Fatalf("%+v", rep)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func FuzzMemLeaks(f *testing.F) {
	f.Add(int64(1), int64(2), int64(3), int64(4))
	f.Fuzz(func(t *testing.T, a, b, c, d int64) {
		ss := []MemSample{{Host: "h", Round: 1, Procs: []Proc{{1, "P", a}}}, {Host: "h", Round: 2, Procs: []Proc{{1, "P", b}}}, {Host: "h", Round: 3, Procs: []Proc{{1, "P", c}}}, {Host: "h", Round: 4, Procs: []Proc{{1, "P", d}}}}
		_ = MemLeaks(ss, LeakOptions{}).Text()
	})
}
