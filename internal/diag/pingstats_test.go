package diag

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// La misma secuencia (1, 3, sin respuesta, 2, 6 ms; sin DUP) da el mismo resumen en iputils y en ping.exe es/en:
// mdev es la desviación estándar poblacional (raíz de 3.5); iputils la imprime con 3 decimales.
func TestPingStatsMismoResumenEnTodos(t *testing.T) {
	want := PingSummary{Sent: 5, Received: 4, LossPct: 20, MinMs: 1, AvgMs: 3, MaxMs: 6, MdevMs: math.Sqrt(3.5)}
	for _, c := range []struct {
		file string
		win  bool
	}{{"iputils_nodup.txt", false}, {"winen.txt", true}, {"wines.txt", true}} {
		f, err := os.Open(filepath.Join("testdata", "ping", c.file))
		if err != nil {
			t.Fatal(err)
		}
		p := NewPingStats(c.win)
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			p.Feed(sc.Text())
		}
		f.Close()
		got := p.Summary()
		if got.Sent != want.Sent || got.Received != want.Received || math.Abs(got.LossPct-want.LossPct) > 1e-9 ||
			got.MinMs != want.MinMs || got.AvgMs != want.AvgMs || got.MaxMs != want.MaxMs || math.Abs(got.MdevMs-want.MdevMs) > 1e-3 {
			t.Errorf("%s: got %+v want %+v", c.file, got, want)
		}
	}
}

// Sin «transmitted» (parado con SIGINT antes del resumen) el icmp_seq más alto da los enviados; sin nada, todo en 0.
func TestPingStatsSinResumenFinal(t *testing.T) {
	p := NewPingStats(false)
	p.Feed("64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=2.00 ms")
	p.Feed("From 192.0.2.254 icmp_seq=2 Destination Host Unreachable")
	if s := p.Summary(); s.Sent != 2 || s.Received != 1 || s.LossPct != 50 {
		t.Errorf("%+v", s)
	}
	if s := NewPingStats(true).Summary(); s != (PingSummary{}) {
		t.Errorf("%+v", s)
	}
}

func feedFile(t *testing.T, file string, win bool) *PingStats {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "ping", file))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	p := NewPingStats(win)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p.Feed(sc.Text())
	}
	return p
}

func near(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

// B1: con DUP, los valores son los de la línea rtt de iputils; sin ella (corte duro) se calcula la desviación
// estándar poblacional con los tiempos DUP incluidos, sin contarlos como recibidos.
func TestPingStatsDupIputils(t *testing.T) {
	s := feedFile(t, "iputils.txt", false).Summary()
	if s.Sent != 5 || s.Received != 4 || s.MinMs != 1 || s.AvgMs != 2.8 || s.MaxMs != 6 || s.MdevMs != 1.72 {
		t.Errorf("con línea rtt: %+v", s)
	}
	p := NewPingStats(false)
	for _, l := range []string{
		"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=1.00 ms",
		"64 bytes from 192.0.2.1: icmp_seq=2 ttl=64 time=3.00 ms",
		"64 bytes from 192.0.2.1: icmp_seq=4 ttl=64 time=2.00 ms",
		"64 bytes from 192.0.2.1: icmp_seq=4 ttl=64 time=2.00 ms (DUP!)",
		"64 bytes from 192.0.2.1: icmp_seq=5 ttl=64 time=6.00 ms",
	} {
		p.Feed(l)
	}
	s = p.Summary()
	if s.Sent != 5 || s.Received != 4 || s.MinMs != 1 || !near(s.AvgMs, 2.8, 1e-9) || s.MaxMs != 6 || !near(s.MdevMs, math.Sqrt(2.96), 1e-9) {
		t.Errorf("corte duro: %+v", s)
	}
}

// B2, M1: «<1ms» cuenta 0 ms; «tiempo<1m» (sin «s»), IPv6 sin «bytes=» y todas las variantes dan el mismo resumen.
func TestPingStatsWindowsVariantes(t *testing.T) {
	for _, f := range []string{"winen4lt.txt", "wines4lt.txt", "winen6.txt", "wines6.txt"} {
		s := feedFile(t, f, true).Summary()
		if s.Sent != 4 || s.Received != 4 || s.MinMs != 0 || s.MaxMs != 1 || s.AvgMs != 0.5 || s.MdevMs != 0.5 {
			t.Errorf("%s: %+v", f, s)
		}
	}
}

// M2: icmp_seq da la vuelta en 65535; los envíos siguen creciendo (y el tope de envíos se puede disparar).
func TestPingStatsSeqDaLaVuelta(t *testing.T) {
	p := NewPingStats(false)
	var n int64
	for _, seq := range []int{65534, 65535, 0, 1, 2} {
		n = p.Feed(fmt.Sprintf("64 bytes from 192.0.2.1: icmp_seq=%d ttl=64 time=1.00 ms", seq))
	}
	if n != 65538 || p.Summary().Sent != 65538 {
		t.Errorf("n=%d %+v", n, p.Summary())
	}
	// Un DUP tardío de antes de la vuelta no infla la cuenta.
	if n = p.Feed("64 bytes from 192.0.2.1: icmp_seq=65535 ttl=64 time=1.00 ms (DUP!)"); n != 65538 {
		t.Errorf("DUP tardío: %d", n)
	}
}

// M3: con size de 0 a 15 iputils no imprime time=: la respuesta cuenta, sin tiempo.
func TestPingStatsSinTiempo(t *testing.T) {
	p := NewPingStats(false)
	p.Feed("8 bytes from 192.0.2.1: icmp_seq=1 ttl=64")
	p.Feed("16 bytes from 192.0.2.1: icmp_seq=2 ttl=64 time=4.00 ms")
	if s := p.Summary(); s.Sent != 2 || s.Received != 2 || s.MinMs != 4 || s.MaxMs != 4 || s.AvgMs != 4 {
		t.Errorf("%+v", s)
	}
}

// L2: desbordes y números absurdos se ignoran.
func TestPingStatsNumerosAbsurdos(t *testing.T) {
	p := NewPingStats(false)
	for _, l := range []string{
		"64 bytes from 192.0.2.1: icmp_seq=99999999999999999999 ttl=64 time=1.00 ms",
		"64 bytes from 192.0.2.1: icmp_seq=2000000000 ttl=64 time=1.00 ms",
		"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=" + strings.Repeat("9", 400) + " ms",
		"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=20000000.0 ms",
		"64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=1.2.3 ms",
		"From 192.0.2.254 icmp_seq=99999999999999999999 Destination Host Unreachable",
		"99999999999999999999 packets transmitted, 0 received",
	} {
		p.Feed(l)
	}
	if s := p.Summary(); s != (PingSummary{}) {
		t.Errorf("linux: %+v", s)
	}
	w := NewPingStats(true)
	w.Feed("Reply from 192.0.2.1: bytes=32 time=" + strings.Repeat("9", 400) + "ms TTL=64")
	w.Feed("Reply from 192.0.2.1: bytes=32 time=99999999999ms TTL=64")
	if s := w.Summary(); s != (PingSummary{}) {
		t.Errorf("windows: %+v", s)
	}
}

// L5: (BAD CHECKSUM!) no cuenta como recibida, igual que en iputils.
func TestPingStatsBadChecksum(t *testing.T) {
	p := NewPingStats(false)
	p.Feed("64 bytes from 192.0.2.1: icmp_seq=1 ttl=64 time=1.00 ms (BAD CHECKSUM!)")
	p.Feed("64 bytes from 192.0.2.1: icmp_seq=2 ttl=64 time=3.00 ms")
	if s := p.Summary(); s.Sent != 2 || s.Received != 1 || s.LossPct != 50 || s.MinMs != 3 {
		t.Errorf("%+v", s)
	}
}
