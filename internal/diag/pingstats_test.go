package diag

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// La misma secuencia (1, 3, sin respuesta, 2, 6 ms) da el mismo resumen en iputils y en ping.exe es/en.
func TestPingStatsMismoResumenEnTodos(t *testing.T) {
	want := PingSummary{Sent: 5, Received: 4, LossPct: 20, MinMs: 1, AvgMs: 3, MaxMs: 6, MdevMs: 1.5}
	for _, c := range []struct {
		file string
		win  bool
	}{{"iputils.txt", false}, {"winen.txt", true}, {"wines.txt", true}} {
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
			got.MinMs != want.MinMs || got.AvgMs != want.AvgMs || got.MaxMs != want.MaxMs || math.Abs(got.MdevMs-want.MdevMs) > 1e-9 {
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
