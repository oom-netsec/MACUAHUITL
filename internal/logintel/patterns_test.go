package logintel

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"%LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down":                     "%LINK-3-UPDOWN: Interface <if>, changed state to down",
		"%LINK-3-UPDOWN: Interface Gi1/0/24.100, changed state to up":                               "%LINK-3-UPDOWN: Interface <if>, changed state to up",
		"%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Vlan10 from FULL to DOWN":                       "%OSPF-5-ADJCHG: Process <n>, Nbr <ip> on <if> from FULL to DOWN",
		"%SW_MATM-4-MACFLAP_NOTIF: Host 0011.2233.4455 in vlan 20 is flapping":                      "%SW_MATM-4-MACFLAP_NOTIF: Host <mac> in vlan <n> is flapping",
		"%X-4-Y: peer aa:bb:cc:dd:ee:ff at 192.0.2.1:179 mask 10.0.0.0/24":                          "%X-4-Y: peer <mac> at <ip> mask <ip>",
		"%X-4-Y: neighbor 2001:db8::1 and fe80::1%Gi0/1 seen":                                       "%X-4-Y: neighbor <ip6> and <ip6>%<if> seen",
		"%SYS-2-MALLOCFAIL: Memory allocation of 65552 bytes failed from 0x1A2B3C4, pool Processor": "%SYS-2-MALLOCFAIL: Memory allocation of <n> bytes failed from <hex>, pool Processor",
		"%SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.0.2.50)":                    "%SYS-5-CONFIG_I: Configured from console by admin on vty<n> (<ip>)",
		"%X-4-Y: Port-channel2 Tunnel0.100 Foo12 xVlan10 show-Gi0/1":                                "%X-4-Y: <if> <if> Foo<n> xVlan<n> show-<if>",
		"sin mnemónico 12 veces en 10.1.1.1":                                                        "sin mnemónico <n> veces en <ip>",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q)\n got  %q\n want %q", in, got, want)
		}
	}
	// El mnemónico no se toca aunque lleve dígitos.
	if got := Normalize("%C4K_IOSMODPORTMAN-4-X2: hola 3"); !strings.HasPrefix(got, "%C4K_IOSMODPORTMAN-4-X2:") {
		t.Errorf("mnemónico alterado: %q", got)
	}
	if got := Normalize(strings.Repeat("1 ", 5000)); len(got) > 4*MaxText {
		t.Errorf("sin tope: %d", len(got))
	}
}

func TestParseLinesShowLogging(t *testing.T) {
	b, _ := os.ReadFile("testdata/show_logging_3560cx.txt")
	es, st := ParseLines(string(b), ParseOptions{Host: "sw-lab", Now: now})
	if len(es) != 13 || st.Parsed != 13 || st.WithTime != 13 {
		t.Fatalf("entradas %d stats %+v", len(es), st)
	}
	e := es[1]
	if e.Host != "sw-lab" || e.Mnemonic != "%LINK-3-UPDOWN" || e.Severity != 3 || !e.At.Equal(time.Date(2026, 11, 6, 10, 0, 1, 100_000_000, time.UTC)) {
		t.Fatalf("%+v", e)
	}
	if !strings.HasPrefix(e.Text, "%LINK-3-UPDOWN: Interface GigabitEthernet0/3") {
		t.Fatalf("texto %q", e.Text)
	}
	if st.Skipped < 10 {
		t.Fatalf("la cabecera de show logging debe contarse como omitida: %+v", st)
	}
	// Un mes futuro (log de diciembre leído en noviembre) cae en el año anterior.
	es, _ = ParseLines("*Dec 31 23:59:59.000: %LINK-3-UPDOWN: Interface Gi0/1, changed state to up", ParseOptions{Now: now})
	if es[0].At.Year() != 2025 {
		t.Fatalf("año %d", es[0].At.Year())
	}
}

func TestParseLinesFormatoDelReceptor(t *testing.T) {
	in := "2026-11-06T10:00:00.250Z 192.0.2.11:514 <187>1234: Nov  6 09:59:00.100: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n" +
		"2026-11-06T10:00:01Z [2001:db8::5]:514 <189>%SYS-5-CONFIG_I: Configured from console\n" +
		"2026-11-06T10:00:02Z 192.0.2.12:514 mensaje libre sin mnemónico\n" +
		"basura\n"
	es, st := ParseLines(in, ParseOptions{Now: now})
	if len(es) != 3 || st.Skipped != 1 {
		t.Fatalf("%d %+v", len(es), st)
	}
	if es[0].Host != "192.0.2.11" || !es[0].At.Equal(time.Date(2026, 11, 6, 10, 0, 0, 250_000_000, time.UTC)) || es[0].Mnemonic != "%LINK-3-UPDOWN" {
		t.Fatalf("%+v", es[0])
	}
	if es[0].Text != "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down" {
		t.Fatalf("texto %q", es[0].Text)
	}
	if es[1].Host != "2001:db8::5" || es[1].Severity != 5 {
		t.Fatalf("%+v", es[1])
	}
	if es[2].Mnemonic != "" || es[2].Severity != -1 {
		t.Fatalf("%+v", es[2])
	}
}

func TestParseLinesSinMarcaDeTiempo(t *testing.T) {
	es, st := ParseLines("%LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n", ParseOptions{Now: now})
	if len(es) != 1 || !es[0].At.IsZero() || st.WithTime != 0 {
		t.Fatalf("%+v %+v", es, st)
	}
}

func TestParseLinesTopes(t *testing.T) {
	var b strings.Builder
	for i := 0; i < MaxLines+10; i++ {
		b.WriteString("%LINK-3-UPDOWN: Interface Gi0/1, changed state to up\n")
	}
	es, st := ParseLines(b.String(), ParseOptions{Now: now})
	if len(es) != MaxLines || !st.Truncated {
		t.Fatalf("%d %+v", len(es), st)
	}
	es, _ = ParseLines("%X-3-Y: "+strings.Repeat("a", 5*MaxText), ParseOptions{Now: now})
	if len(es[0].Text) > MaxText {
		t.Fatalf("línea sin recortar: %d", len(es[0].Text))
	}
}

// capture arma n repeticiones de un mensaje por segundo a partir de t0.
func capture(host, msg string, t0 time.Time, n int, step time.Duration) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "%s %s:514 <187>%s\n", t0.Add(time.Duration(i)*step).Format(time.RFC3339Nano), host, msg)
	}
	return b.String()
}

func TestGroupAgrupaPorPatronYMarcaRafagas(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	in := capture("192.0.2.1", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/1, changed state to down", t0, 6, 2*time.Second) +
		capture("192.0.2.2", "%LINK-3-UPDOWN: Interface GigabitEthernet1/0/7, changed state to down", t0.Add(time.Second), 3, 20*time.Second) +
		capture("192.0.2.1", "%SYS-5-CONFIG_I: Configured from console by admin", t0, 1, 0)
	es, _ := ParseLines(in, ParseOptions{Now: now})
	rep := Group(es, GroupOptions{})
	if len(rep.Patterns) != 2 {
		t.Fatalf("patrones %d: %+v", len(rep.Patterns), rep.Patterns)
	}
	p := rep.Patterns[0]
	if p.Mnemonic != "%LINK-3-UPDOWN" || p.Count != 9 || p.HostCount != 2 || !strings.Contains(p.Pattern, "Interface <if>") {
		t.Fatalf("%+v", p)
	}
	if !p.Burst || p.Episodes != 1 || p.Peak < 5 {
		t.Fatalf("ráfaga: %+v", p)
	}
	if p.KB == nil || p.KB.ID != "%LINK-3-UPDOWN" {
		t.Fatalf("sin ficha de la base: %+v", p.KB)
	}
	q := rep.Patterns[1]
	if q.Burst || q.Count != 1 {
		t.Fatalf("%+v", q)
	}
}

func TestGroupInestabilidadSonVariasRafagas(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	msg := "%OSPF-5-ADJCHG: Process 1, Nbr 10.0.0.2 on Vlan10 from FULL to DOWN"
	one := capture("192.0.2.1", msg, t0, 5, time.Second)
	two := one + capture("192.0.2.1", msg, t0.Add(10*time.Minute), 5, time.Second)
	for name, c := range map[string]struct {
		in            string
		burst, unstab bool
		eps           int
	}{"una ráfaga": {one, true, false, 1}, "dos ráfagas": {two, true, true, 2}} {
		es, _ := ParseLines(c.in, ParseOptions{Now: now})
		p := Group(es, GroupOptions{}).Patterns[0]
		if p.Burst != c.burst || p.Unstable != c.unstab || p.Episodes != c.eps {
			t.Errorf("%s: %+v", name, p)
		}
	}
	// El umbral y la ventana son configurables: 5 en 60 s con N=6 ya no es ráfaga.
	es, _ := ParseLines(one, ParseOptions{Now: now})
	if p := Group(es, GroupOptions{BurstCount: 6}).Patterns[0]; p.Burst {
		t.Fatalf("N=6: %+v", p)
	}
	// Cinco eventos separados 20 s no caben en una ventana de 60 s con N=5 (4 por ventana a lo más).
	es, _ = ParseLines(capture("192.0.2.1", msg, t0, 5, 20*time.Second), ParseOptions{Now: now})
	if p := Group(es, GroupOptions{}).Patterns[0]; p.Burst || p.Peak != 4 {
		t.Fatalf("lento: %+v", p)
	}
	if p := Group(es, GroupOptions{BurstWindow: 2 * time.Minute}).Patterns[0]; !p.Burst {
		t.Fatalf("ventana de 2 min: %+v", p)
	}
}

func TestGroupSinHoraNoMarcaRafagas(t *testing.T) {
	es, _ := ParseLines(strings.Repeat("%LINK-3-UPDOWN: Interface Gi0/1, changed state to up\n", 20), ParseOptions{Now: now})
	rep := Group(es, GroupOptions{})
	if p := rep.Patterns[0]; p.Count != 20 || p.Burst || p.Peak != 0 {
		t.Fatalf("%+v", p)
	}
	if len(rep.Warnings) == 0 {
		t.Fatal("debe avisar que sin hora no se detectan ráfagas")
	}
}

func TestGroupTopeDePatrones(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "%%X-3-Y%d: algo\n", i) // 50 mnemónicos distintos
	}
	es, _ := ParseLines(b.String(), ParseOptions{Now: now})
	rep := Group(es, GroupOptions{MaxPatterns: 10})
	if len(rep.Patterns) != 10 || rep.Overflow != 40 || len(rep.Warnings) == 0 {
		t.Fatalf("%d overflow=%d", len(rep.Patterns), rep.Overflow)
	}
}

func FuzzParseGroup(f *testing.F) {
	b, _ := os.ReadFile("testdata/show_logging_3560cx.txt")
	f.Add(string(b))
	f.Add("2026-11-06T10:00:00Z 192.0.2.1:514 <187>%X-3-Y: 0x 1.2.3.4/99 ::: fe80::1%Gi0/1")
	f.Add("<<<<>>> 0011.2233 aa:bb:cc \x00\xff")
	f.Fuzz(func(t *testing.T, s string) {
		es, _ := ParseLines(s, ParseOptions{Now: now})
		rep := Group(es, GroupOptions{})
		if len(rep.Patterns) > 2000 {
			t.Fatal("patrones sin tope")
		}
		_ = Normalize(s)
	})
}

func TestSeveridadDelPRIYMinimaDelGrupo(t *testing.T) {
	in := "2026-11-06T10:00:00Z 192.0.2.1:514 <187>algo raro 1\n2026-11-06T10:00:01Z 192.0.2.1:514 <190>algo raro 2\n"
	es, _ := ParseLines(in, ParseOptions{Now: now})
	if es[0].Severity != 3 || es[1].Severity != 6 {
		t.Fatalf("PRI %d y %d, quería 3 y 6", es[0].Severity, es[1].Severity)
	}
	if p := Group(es, GroupOptions{}).Patterns[0]; p.Severity != 3 || p.Count != 2 {
		t.Fatalf("%+v", p)
	}
}

func TestLosInestablesVanPrimero(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	big := capture("192.0.2.1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down", t0, 30, time.Second) // más mensajes, pero una sola ráfaga
	osc := capture("192.0.2.1", "%OSPF-5-ADJCHG: Nbr 1.1.1.1 down", t0, 5, time.Second) + capture("192.0.2.1", "%OSPF-5-ADJCHG: Nbr 1.1.1.1 down", t0.Add(time.Hour), 5, time.Second)
	es, _ := ParseLines(big+osc, ParseOptions{Now: now})
	ps := Group(es, GroupOptions{}).Patterns
	if ps[0].Mnemonic != "%OSPF-5-ADJCHG" || !ps[0].Unstable || !ps[1].Burst || ps[1].Unstable {
		t.Fatalf("orden: %s unstable=%v / %s burst=%v", ps[0].Mnemonic, ps[0].Unstable, ps[1].Mnemonic, ps[1].Burst)
	}
}

func TestReportText(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	es, _ := ParseLines(capture("192.0.2.1", "%LINK-3-UPDOWN: Interface Gi0/1, changed state to down", t0, 5, time.Second), ParseOptions{Now: now})
	out := Group(es, GroupOptions{}).Text()
	for _, w := range []string{"[RÁFAGA] x5", "Interface <if>", "pico: 5", "equipos (1): 192.0.2.1", "base de mensajes:", "Ráfaga: 5 del mismo patrón en 1m0s"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q en:\n%s", w, out)
		}
	}
}

// BenchmarkGroup200k: el tope de líneas de una fuente (modo en vivo: se repite cada pocos segundos).
func BenchmarkGroup200k(b *testing.B) {
	var sb strings.Builder
	for i := range MaxLines {
		switch i % 4 {
		case 0:
			fmt.Fprintf(&sb, "*Nov  4 09:58:%02d.%03d: %%SYS-5-CONFIG_I: Configured from console by admin on vty0 (10.0.0.%d)\n", i%60, i%1000, i%250)
		case 1:
			fmt.Fprintf(&sb, "*Nov  4 09:58:%02d.%03d: %%LINK-3-UPDOWN: Interface GigabitEthernet0/%d, changed state to up\n", i%60, i%1000, i%48)
		case 2:
			fmt.Fprintf(&sb, "*Nov  4 09:58:%02d.%03d: %%SPANTREE-5-TOPOTRAP: Topology Change Trap for vlan %d\n", i%60, i%1000, i%4000)
		default:
			fmt.Fprintf(&sb, "*Nov  4 09:58:%02d.%03d: %%OSPF-5-ADJCHG: Process 1, Nbr 192.0.2.%d on Vlan%d from LOADING to FULL, Loading Done\n", i%60, i%1000, i%250, i%100)
		}
	}
	es, _ := ParseLines(sb.String(), ParseOptions{Now: now})
	b.ResetTimer()
	for range b.N {
		Group(es, GroupOptions{})
	}
}

// El número de secuencia y el uptime que van antes del mnemónico no deben partir el patrón.
func TestCabeceraConSecuenciaYUptimeEsUnSoloPatron(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var sb strings.Builder
	for i := range 6 {
		fmt.Fprintf(&sb, "%s 192.0.2.1:514 <187>0000%02d: %dd0%dh: %%LINK-3-UPDOWN: Interface Gi0/1, changed state to down\n", t0.Add(time.Duration(i)*time.Second).Format(time.RFC3339), 10+i, 1+i/3, 2+i%3)
	}
	es, _ := ParseLines(sb.String(), ParseOptions{Now: now})
	rep := Group(es, GroupOptions{})
	if len(rep.Patterns) != 1 || rep.Patterns[0].Count != 6 || !rep.Patterns[0].Burst {
		t.Fatalf("%d patrones: %+v", len(rep.Patterns), rep.Patterns)
	}
	if got := rep.Patterns[0].Pattern; !strings.Contains(got, "%LINK-3-UPDOWN: Interface <if>") || strings.Contains(got, "0000") {
		t.Fatalf("patrón %q", got)
	}
}

// Un mensaje periódico (cada 15 s con ±0,7 s de variación) y umbral 5 en 60 s: el conteo de la
// ventana oscila entre 4 y 5, pero eso no es un problema que vuelve.
func TestMensajePeriodicoConVariacionNoEsInestable(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	jit := []float64{0.7, -0.7, 0, 0.7, -0.7, -0.7, 0.7}
	var sb strings.Builder
	for i := range 80 {
		at := t0.Add(time.Duration(i)*15*time.Second + time.Duration(jit[i%len(jit)]*float64(time.Second)))
		fmt.Fprintf(&sb, "%s 192.0.2.1:514 <189>%%SYS-5-CONFIG_I: Configured from console by admin on vty0\n", at.Format(time.RFC3339Nano))
	}
	es, _ := ParseLines(sb.String(), ParseOptions{Now: now})
	p := Group(es, GroupOptions{BurstCount: 5, BurstWindow: 60 * time.Second}).Patterns[0]
	if p.Unstable || p.Episodes > 1 {
		t.Fatalf("periódico marcado como inestable: episodios %d pico %d", p.Episodes, p.Peak)
	}
}

// Dos ráfagas separadas por más de una ventana siguen siendo inestables.
func TestRafagasSeparadasPorUnaVentanaSiSonInestables(t *testing.T) {
	t0 := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	var ts []time.Time
	for _, base := range []time.Duration{0, 5 * time.Minute} {
		for i := range 5 {
			ts = append(ts, t0.Add(base+time.Duration(i)*time.Second))
		}
	}
	if _, ep := peaks(ts, 60*time.Second, 5); ep != 2 {
		t.Fatalf("episodios %d", ep)
	}
	// Un bache de 30 s dentro de la misma ventana no abre otro episodio.
	ts = ts[:0]
	for _, base := range []time.Duration{0, 40 * time.Second} {
		for i := range 5 {
			ts = append(ts, t0.Add(base+time.Duration(i)*time.Second))
		}
	}
	if _, ep := peaks(ts, 60*time.Second, 5); ep != 1 {
		t.Fatalf("episodios con bache corto %d", ep)
	}
}
