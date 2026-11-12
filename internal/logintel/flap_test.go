package logintel

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFlapsDelShowLoggingDelCatalyst(t *testing.T) {
	b, _ := os.ReadFile("testdata/show_logging_3560cx.txt")
	es, _ := ParseLines(string(b), ParseOptions{Host: "sw-lab", Now: now})
	rep := Flaps(es, FlapOptions{})
	if len(rep.Flaps) != 1 {
		t.Fatalf("%d flaps: %+v", len(rep.Flaps), rep.Flaps)
	}
	f := rep.Flaps[0]
	// Gi0/3 cae 3 veces en 20 s y cada caída dura 350 ms; LINEPROTO no se cuenta aparte.
	if f.Host != "sw-lab" || f.Interface != "Gi0/3" || f.Peak != 6 || f.Total != 6 || f.Episodes != 1 {
		t.Fatalf("%+v", f)
	}
	if f.Sequence != "down up down up down up" {
		t.Fatalf("secuencia %q", f.Sequence)
	}
	if f.KB == nil || f.KB.ID != "%LINK-3-UPDOWN" {
		t.Fatalf("sin ficha: %+v", f.KB)
	}
	if rep.Transitions != 8 || rep.Interfaces != 2 { // Gi0/3 (6 LINK) + Gi0/7 (2)
		t.Fatalf("totales: %+v", rep)
	}
}

func link(host, ifc, state string, at time.Time) string {
	return fmt.Sprintf("%s %s:514 <187>%%LINK-3-UPDOWN: Interface %s, changed state to %s\n", at.Format(time.RFC3339Nano), host, ifc, state)
}

func TestFlapsUmbralYVentana(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	// 3 transiciones en 30 ms son flapping aunque cada caída dure milisegundos.
	in := link("1.1.1.1", "GigabitEthernet1/0/1", "down", t0) + link("1.1.1.1", "GigabitEthernet1/0/1", "up", t0.Add(10*time.Millisecond)) + link("1.1.1.1", "GigabitEthernet1/0/1", "down", t0.Add(30*time.Millisecond))
	es, _ := ParseLines(in, ParseOptions{Now: now})
	if rep := Flaps(es, FlapOptions{}); len(rep.Flaps) != 1 || rep.Flaps[0].Peak != 3 {
		t.Fatalf("ms: %+v", rep.Flaps)
	}
	// Dos transiciones no alcanzan.
	if rep := Flaps(es[:2], FlapOptions{}); len(rep.Flaps) != 0 {
		t.Fatalf("2 transiciones: %+v", rep.Flaps)
	}
	// Tres transiciones separadas 40 s caben 2 por ventana de 60 s: no hay flapping; con ventana de 2 min, sí.
	in = link("1.1.1.1", "Gi1/0/1", "down", t0) + link("1.1.1.1", "Gi1/0/1", "up", t0.Add(40*time.Second)) + link("1.1.1.1", "Gi1/0/1", "down", t0.Add(80*time.Second))
	es, _ = ParseLines(in, ParseOptions{Now: now})
	if rep := Flaps(es, FlapOptions{}); len(rep.Flaps) != 0 {
		t.Fatalf("lento: %+v", rep.Flaps)
	}
	if rep := Flaps(es, FlapOptions{Window: 2 * time.Minute}); len(rep.Flaps) != 1 {
		t.Fatalf("ventana 2 min: %+v", rep.Flaps)
	}
	if rep := Flaps(es, FlapOptions{Window: 2 * time.Minute, Count: 4}); len(rep.Flaps) != 0 {
		t.Fatalf("N=4: %+v", rep.Flaps)
	}
}

func TestFlapsSeparaEquiposEInterfacesYUsaLineprotoSiNoHayLink(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := 0; i < 3; i++ { // dos equipos, la misma interfaz, 2 transiciones cada uno: ninguno llega a 3
		b.WriteString(link("1.1.1.1", "Gi1/0/1", "down", t0.Add(time.Duration(i)*time.Second)))
		b.WriteString(link("2.2.2.2", "Gi1/0/1", "down", t0.Add(time.Duration(i)*time.Second+time.Millisecond)))
	}
	es, _ := ParseLines(b.String(), ParseOptions{Now: now})
	if rep := Flaps(es, FlapOptions{Count: 4}); len(rep.Flaps) != 0 {
		t.Fatalf("mezcló equipos: %+v", rep.Flaps)
	}
	if rep := Flaps(es, FlapOptions{}); len(rep.Flaps) != 2 {
		t.Fatalf("debían ser 2: %+v", rep.Flaps)
	}
	var lp strings.Builder
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&lp, "%s 3.3.3.3:514 <189>%%LINEPROTO-5-UPDOWN: Line protocol on Interface Vlan10, changed state to up\n", t0.Add(time.Duration(i)*time.Second).Format(time.RFC3339))
	}
	es, _ = ParseLines(lp.String(), ParseOptions{Now: now})
	if rep := Flaps(es, FlapOptions{}); len(rep.Flaps) != 1 || rep.Flaps[0].Interface != "Vlan10" {
		t.Fatalf("lineproto: %+v", rep.Flaps)
	}
}

func TestFlapsSinHoraSeMarcaComoPosible(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 4; i++ {
		b.WriteString("%LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n")
	}
	es, _ := ParseLines(b.String(), ParseOptions{Host: "sw", Now: now})
	rep := Flaps(es, FlapOptions{})
	if len(rep.Flaps) != 1 || !rep.Flaps[0].NoTime || rep.Flaps[0].Total != 4 || rep.Flaps[0].Peak != 0 || len(rep.Warnings) == 0 {
		t.Fatalf("%+v", rep)
	}
	if rep := Flaps(es[:2], FlapOptions{}); len(rep.Flaps) != 0 {
		t.Fatalf("2 sin hora: %+v", rep.Flaps)
	}
}

func TestFlapsIgnoraAdministrativoYBasura(t *testing.T) {
	in := "%LINK-5-CHANGED: Interface Gi0/1, changed state to administratively down\n%LINK-3-UPDOWN: Interface , changed state to up\n%LINK-3-UPDOWN: Interface Gi0/1, changed state to sideways\n"
	es, _ := ParseLines(in, ParseOptions{Now: now})
	if rep := Flaps(es, FlapOptions{Count: 1}); len(rep.Flaps) != 0 || rep.Transitions != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestCounterJumps(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	mk := func(round int, resets, lost, carrier int64) CounterSample {
		return CounterSample{Host: "sw", Round: round, At: t0.Add(time.Duration(round) * 10 * time.Minute), Interface: "Gi0/3",
			Counters: map[string]int64{"interface resets": resets, "lost carrier": lost, "carrier transitions": carrier}}
	}
	jumps := CounterJumps([]CounterSample{mk(1, 1, 0, 5), mk(2, 8, 1, 5), mk(3, 8, 1, 9)}, 3)
	if len(jumps) != 2 {
		t.Fatalf("%+v", jumps)
	}
	j := jumps[0]
	if j.Counter != "interface resets" || j.FromRound != 1 || j.ToRound != 2 || j.Delta != 7 || j.PerHour != 42 {
		t.Fatalf("%+v", j)
	}
	if jumps[1].Counter != "carrier transitions" || jumps[1].Delta != 4 || jumps[1].ToRound != 3 {
		t.Fatalf("%+v", jumps[1])
	}
	// Por debajo del umbral no se avisa; el umbral por defecto es 3.
	if len(CounterJumps([]CounterSample{mk(1, 1, 0, 5), mk(2, 3, 2, 5)}, 0)) != 0 {
		t.Fatal("delta 2 con umbral por defecto")
	}
	if len(CounterJumps([]CounterSample{mk(1, 1, 0, 5), mk(2, 3, 2, 5)}, 2)) != 2 {
		t.Fatal("umbral 2")
	}
	// Un contador que baja se borró (clear counters o recarga): no es un salto.
	js := CounterJumps([]CounterSample{mk(1, 50, 0, 0), mk(2, 2, 0, 0), mk(3, 9, 0, 0)}, 3)
	if len(js) != 1 || js[0].Delta != 7 || js[0].FromRound != 2 {
		t.Fatalf("tras reinicio: %+v", js)
	}
	// Las rondas llegan desordenadas y de varios equipos e interfaces.
	other := CounterSample{Host: "sw2", Round: 1, At: t0, Interface: "Gi0/3", Counters: map[string]int64{"interface resets": 0}}
	other2 := CounterSample{Host: "sw2", Round: 2, At: t0.Add(time.Hour), Interface: "Gi0/3", Counters: map[string]int64{"interface resets": 3}}
	js = CounterJumps([]CounterSample{mk(2, 8, 1, 5), other2, mk(1, 1, 0, 5), other}, 3)
	if len(js) != 2 || js[0].Host != "sw" || js[1].Host != "sw2" || js[1].PerHour != 3 {
		t.Fatalf("%+v", js)
	}
}

func FuzzFlaps(f *testing.F) {
	b, _ := os.ReadFile("testdata/show_logging_3560cx.txt")
	f.Add(string(b))
	f.Add("%LINK-3-UPDOWN: Interface " + strings.Repeat("Gi", 100) + ", changed state to up")
	f.Fuzz(func(t *testing.T, s string) {
		es, _ := ParseLines(s, ParseOptions{Now: now})
		_ = Flaps(es, FlapOptions{})
	})
}

func TestFlapsOrdenaPorPicoYAcotaLaSecuencia(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var b strings.Builder
	for i := 0; i < 8; i++ { // pico alto, pocas en total
		b.WriteString(link("1.1.1.1", "Gi0/1", "down", t0.Add(time.Duration(i)*time.Second)))
	}
	for i := 0; i < 20; i++ { // muchas en total, pico bajo (una cada 10 s)
		b.WriteString(link("2.2.2.2", "Gi0/2", "up", t0.Add(time.Duration(i)*10*time.Second)))
	}
	es, _ := ParseLines(b.String(), ParseOptions{Now: now})
	rep := Flaps(es, FlapOptions{Window: 30 * time.Second})
	if len(rep.Flaps) != 2 || rep.Flaps[0].Interface != "Gi0/1" || rep.Flaps[0].Peak != 8 || rep.Flaps[1].Peak != 4 {
		t.Fatalf("%+v", rep.Flaps)
	}
	if n := len(strings.Fields(rep.Flaps[1].Sequence)); n != maxSequence {
		t.Fatalf("secuencia de %d estados", n)
	}
	if !strings.Contains(rep.Text(), "[FLAPPING] 1.1.1.1 Gi0/1") || !strings.Contains(JumpsText(nil), "Ningún") {
		t.Fatal(rep.Text())
	}
}
