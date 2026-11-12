package logintel

import (
	"fmt"
	"strings"
	"testing"
)

// debugs arma la salida de un debug ip ospf adj de un 3560CX: 60 hellos casi idénticos, ruido de CDP y dos rarezas.
func debugs() string {
	var b strings.Builder
	for i := 0; i < 60; i++ {
		fmt.Fprintf(&b, "*Nov  6 10:%02d:%02d.%03d: OSPF-1 ADJ   Gi0/1: Rcv hello from 10.0.0.2 area 0 10.0.12.2\n", i/60, i%60, i*7)
		if i%10 == 0 {
			fmt.Fprintf(&b, "*Nov  6 10:00:%02d.000: CDP-PA: Packet received from sw%d on interface Gi0/%d\n", i%60, i, i%4)
		}
	}
	b.WriteString("*Nov  6 10:01:01.000: OSPF-1 ADJ   Gi0/1: Mismatched hello parameters from 10.0.12.2\n")
	b.WriteString("*Nov  6 10:01:02.000: OSPF-1 ADJ   Gi0/1: Nbr 10.0.0.2 address 10.0.12.2 is dead, state DOWN\n")
	b.WriteString("\n   \n")
	return b.String()
}

func TestDebugFilterAgrupaOcultaRuidoYMarcaAnomalias(t *testing.T) {
	rep := FilterDebug(debugs(), DebugOptions{Noise: []string{"cdp-pa"}})
	if rep.Lines != 70 || rep.Blank != 2 || rep.Hidden != 6 {
		t.Fatalf("totales: %+v", rep)
	}
	if len(rep.Groups) != 3 || rep.Groups[0].Count != 60 || !strings.Contains(rep.Groups[0].Pattern, "Rcv hello from <ip> area <n> <ip>") {
		t.Fatalf("grupos: %+v", rep.Groups)
	}
	if len(rep.Anomalies) != 2 {
		t.Fatalf("anomalías: %+v", rep.Anomalies)
	}
	a := rep.Anomalies[0]
	if a.Line != 67 || !strings.Contains(a.Reason, "rara") || !strings.Contains(a.Reason, "alarma") || !strings.Contains(a.Text, "Mismatched") || a.FamilyCount != 62 {
		t.Fatalf("%+v", a)
	}
	if rep.Anomalies[1].Line != 68 || !strings.Contains(rep.Anomalies[1].Text, "is dead") {
		t.Fatalf("%+v", rep.Anomalies[1])
	}
	// Los hellos repetidos no son anomalía ni aunque haya 60.
	for _, a := range rep.Anomalies {
		if strings.Contains(a.Text, "Rcv hello") {
			t.Fatalf("anomalía falsa: %+v", a)
		}
	}
	if !strings.Contains(rep.Text(), "líneas ocultas por ruido") {
		t.Fatal(rep.Text())
	}
}

func TestDebugFilterSinRuidoNoOculta(t *testing.T) {
	rep := FilterDebug(debugs(), DebugOptions{})
	if rep.Hidden != 0 || len(rep.Groups) != 4 {
		t.Fatalf("%+v", rep)
	}
	// CDP: 6 líneas, familia propia de 6 < 20: no se marca rara aunque sean 1 por patrón.
	for _, a := range rep.Anomalies {
		if strings.Contains(a.Text, "CDP-PA") {
			t.Fatalf("%+v", a)
		}
	}
}

func TestDebugFilterUmbralesConfigurables(t *testing.T) {
	rep := FilterDebug(debugs(), DebugOptions{FamilyMin: 100})
	if len(rep.Anomalies) != 2 { // sin familia frecuente solo quedan las de palabra de alarma
		t.Fatalf("%+v", rep.Anomalies)
	}
	for _, a := range rep.Anomalies {
		if strings.Contains(a.Reason, "rara") || !strings.Contains(a.Reason, "alarma") {
			t.Fatalf("%+v", a)
		}
	}
	rep = FilterDebug(debugs(), DebugOptions{Top: 1})
	if len(rep.Groups) != 1 || rep.GroupsTotal != 4 {
		t.Fatalf("top: %d de %d", len(rep.Groups), rep.GroupsTotal)
	}
}

func TestDebugFilterTopes(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&b, "VERBO%c%c%c algo failed\n", 'a'+i%26, 'a'+(i/26)%26, 'a'+(i/676)%26)
	}
	rep := FilterDebug(b.String(), DebugOptions{})
	if len(rep.Anomalies) != MaxAnomalies || len(rep.Warnings) == 0 {
		t.Fatalf("anomalías %d, avisos %v", len(rep.Anomalies), rep.Warnings)
	}
	noise := make([]string, 200)
	for i := range noise {
		noise[i] = fmt.Sprintf("n%d", i)
	}
	if rep := FilterDebug("x\n", DebugOptions{Noise: noise}); len(rep.Noise) != MaxNoise {
		t.Fatalf("ruido sin tope: %d", len(rep.Noise))
	}
	if rep := FilterDebug("x\n", DebugOptions{Noise: []string{strings.Repeat("a", 1000), "  "}}); len(rep.Noise) != 1 || len(rep.Noise[0]) != MaxNoiseLen {
		t.Fatalf("términos: %q", rep.Noise)
	}
	var many strings.Builder
	for i := 0; i < MaxLines+5; i++ {
		many.WriteString("x\n")
	}
	if rep := FilterDebug(many.String(), DebugOptions{}); rep.Lines != MaxLines || !rep.Truncated {
		t.Fatalf("%d %v", rep.Lines, rep.Truncated)
	}
}

func FuzzFilterDebug(f *testing.F) {
	f.Add(debugs(), "cdp")
	f.Add("\x00\xff<<<>>>"+strings.Repeat("1.2.3.4 ", 100), "")
	f.Fuzz(func(t *testing.T, s, noise string) {
		rep := FilterDebug(s, DebugOptions{Noise: []string{noise}})
		if len(rep.Anomalies) > MaxAnomalies || len(rep.Groups) > 50 {
			t.Fatal("sin tope")
		}
	})
}

// fam arma n líneas de la familia "RIP:" repetidas más las rarezas indicadas (cada una con su cuenta).
func fam(n int, rare map[string]int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("RIP: sending v2 update to 224.0.0.9 via Gi0/1\n")
	}
	for txt, c := range rare {
		for i := 0; i < c; i++ {
			b.WriteString("RIP: " + txt + "\n")
		}
	}
	return b.String()
}

func TestDebugFilterLimitesDeFamiliaYRareza(t *testing.T) {
	has := func(rep DebugReport, sub string) bool {
		for _, a := range rep.Anomalies {
			if strings.Contains(a.Text, sub) {
				return true
			}
		}
		return false
	}
	// Familia de exactamente 20 líneas (17 + 2 + 1): la rareza de 2 apariciones cuenta; la de 3 no.
	rep := FilterDebug(fam(17, map[string]int{"peer reset ok": 2, "route added ok": 1}), DebugOptions{})
	if !has(rep, "peer reset ok") || !has(rep, "route added ok") {
		t.Fatalf("familia de 20: %+v", rep.Anomalies)
	}
	rep = FilterDebug(fam(17, map[string]int{"peer reset ok": 3}), DebugOptions{})
	if has(rep, "peer reset ok") {
		t.Fatalf("3 apariciones no es rara: %+v", rep.Anomalies)
	}
	rep = FilterDebug(fam(16, map[string]int{"peer reset ok": 2, "route added ok": 1}), DebugOptions{}) // 19 líneas
	if len(rep.Anomalies) != 0 {
		t.Fatalf("familia de 19: %+v", rep.Anomalies)
	}
	rep = FilterDebug(fam(16, map[string]int{"peer reset ok": 2, "route added ok": 1}), DebugOptions{FamilyMin: 19, RareMax: 1})
	if !has(rep, "route added ok") || has(rep, "peer reset ok") {
		t.Fatalf("umbrales propios: %+v", rep.Anomalies)
	}
}

func TestDebugFilterPalabrasDeAlarma(t *testing.T) {
	for _, ok := range []string{"received error packet", "ack timeout", "update dropped", "bad checksum", "neighbor lost", "retransmitting update", "Auth failed"} {
		if rep := FilterDebug("RIP: "+ok+"\n", DebugOptions{}); len(rep.Anomalies) != 1 {
			t.Errorf("%q no se marcó", ok)
		}
	}
	for _, no := range []string{"sending update", "errored"[:0] + "terror", "bandwidth ok"} {
		if rep := FilterDebug("RIP: "+no+"\n", DebugOptions{}); len(rep.Anomalies) != 0 {
			t.Errorf("%q se marcó sin motivo: %+v", no, rep.Anomalies)
		}
	}
}

func TestDebugFilterTopeDePatrones(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxPatterns+7; i++ {
		fmt.Fprintf(&b, "TOK%s%s%s%s: x\n", string(rune('a'+i%26)), string(rune('a'+(i/26)%26)), string(rune('a'+(i/676)%26)), string(rune('a'+(i/17576)%26)))
	}
	rep := FilterDebug(b.String(), DebugOptions{})
	if rep.GroupsTotal != maxPatterns || len(rep.Warnings) == 0 {
		t.Fatalf("%d grupos, avisos %v", rep.GroupsTotal, rep.Warnings)
	}
}
