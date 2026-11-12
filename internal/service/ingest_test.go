package service

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
)

func TestIngestOptsDefaults(t *testing.T) {
	l, s, err := IngestOpts{}.Build(context.Background(), "/o/x", "traps_{fecha}_{hora}")
	if err != nil {
		t.Fatal(err)
	}
	if l != (ingest.Limits{}) {
		t.Fatalf("los topes en 0 quedan en 0 (el default lo aplica ingest): %+v", l)
	}
	if s.Dir != "/o/x" || s.Template != "traps_{fecha}_{hora}" || s.RotateBytes != 50<<20 || s.RotateEvery != 0 || s.MaxFiles != 20 || s.Format != "texto" {
		t.Fatalf("sink = %+v", s)
	}
	l, s, err = IngestOpts{RatePerSource: 5, BurstPerSource: 6, RateGlobal: 7, BurstGlobal: 8, QueueSize: 64, RotateMB: 3, RotateMinutes: 2, MaxFiles: 4, NameTemplate: "t_{origen}_{fecha}", Format: "jsonl"}.Build(context.Background(), "/d", "x_{fecha}")
	if err != nil {
		t.Fatal(err)
	}
	if l != (ingest.Limits{PerSource: 5, PerSourceBurst: 6, Global: 7, GlobalBurst: 8, Queue: 64}) ||
		s.RotateBytes != 3<<20 || s.RotateEvery != 2*time.Minute || s.MaxFiles != 4 || s.Template != "t_{origen}_{fecha}" || s.Format != "jsonl" {
		t.Fatalf("%+v %+v", l, s)
	}
}

// Flows usa otros defaults de tasa (un exportador manda muchos más datagramas que un equipo syslog); lo explícito manda.
func TestIngestOptsRateDefaultsOverride(t *testing.T) {
	l, _, err := IngestOpts{DefPerSource: 1000, DefGlobal: 5000}.Build(context.Background(), "/d", "x_{fecha}")
	if err != nil {
		t.Fatal(err)
	}
	if e := l.Effective(); e.PerSource != 1000 || e.PerSourceBurst != 2000 || e.Global != 5000 || e.GlobalBurst != 10000 {
		t.Fatalf("%+v", e)
	}
	l, _, _ = IngestOpts{DefPerSource: 1000, DefGlobal: 5000, RatePerSource: 7, RateGlobal: 9}.Build(context.Background(), "/d", "x_{fecha}")
	if e := l.Effective(); e.PerSource != 7 || e.Global != 9 {
		t.Fatalf("lo explícito debía mandar: %+v", e)
	}
}

func TestIngestOptsRejectsOutOfRange(t *testing.T) {
	for name, o := range map[string]IngestOpts{
		"tasa origen": {RatePerSource: 10001}, "tasa negativa": {RatePerSource: -1}, "ráfaga": {BurstGlobal: 1_000_001},
		"tasa global": {RateGlobal: 100001}, "cola": {QueueSize: 63}, "mb": {RotateMB: 1025}, "mb negativo": {RotateMB: -1},
		"minutos": {RotateMinutes: 10081}, "minutos enormes": {RotateMinutes: 307445736}, "minutos negativos enormes": {RotateMinutes: -307445733},
		"minutos de preferencia enormes": {Prefs: IngestDefaults{RotateMinutes: 307445736}}, "minutos de preferencia negativos": {Prefs: IngestDefaults{RotateMinutes: -307445733}}, "archivos": {MaxFiles: 1001}, "archivos negativo": {MaxFiles: -2},
		"plantilla": {NameTemplate: "../x"}, "sin fecha": {NameTemplate: "solo"}, "formato": {Format: "xml"},
	} {
		_, _, err := o.Build(context.Background(), "/d", "x_{fecha}")
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestIngestDetail(t *testing.T) {
	l, s, _ := IngestOpts{RatePerSource: 10}.Build(context.Background(), "/d", "x_{fecha}")
	got := IngestDetail(l, s, true)
	want := "tasa_origen=10 rafaga_origen=20 tasa_global=1000 rafaga_global=2000 cola=4096 rotar_mb=50 rotar_min=0 plantilla=x_{fecha} max_archivos=20 formato=texto"
	if got != want {
		t.Fatalf("%q", got)
	}
	if got := IngestDetail(l, s, false); got != "tasa_origen=10 rafaga_origen=20 tasa_global=1000 rafaga_global=2000 cola=4096" {
		t.Fatalf("sin archivo: %q", got)
	}
}

func TestDropsProto(t *testing.T) {
	d := ingest.Drops{Total: 6, PorOrigen: 1, Global: 2, ColaLlena: 3, Desde: time.UnixMilli(1234), Top: []ingest.SourceDrops{{Source: "10.0.0.1", Count: 5}}}
	p := DropsProto(d)
	if p.Total != 6 || p.PorOrigen != 1 || p.Global != 2 || p.ColaLlena != 3 || p.SinceMs != 1234 || len(p.Top) != 1 || p.Top[0].Source != "10.0.0.1" || p.Top[0].Count != 5 {
		t.Fatalf("%+v", p)
	}
}

func TestPumpNeverBlocksSenderAndCountsLost(t *testing.T) {
	release := make(chan struct{})
	got := make(chan int, 16)
	p := NewPump(func(m int) error { got <- m; <-release; return nil }, 2)
	done := make(chan struct{})
	go func() {
		for i := range 20 {
			p.Send(i)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Send se bloqueó con el cliente atascado")
	}
	start := time.Now()
	lost := p.Close(100 * time.Millisecond)
	if time.Since(start) > 2*time.Second {
		t.Fatal("Close no respetó la espera")
	}
	close(release)
	if lost != 19 { // 1 en vuelo atascado; los otros 19 no llegaron: 17 al llenarse la cola y 2 que se quedaron en ella al vencer la espera
		t.Fatalf("perdidos = %d", lost)
	}
}

func TestPumpDeliversEverythingWhenClientKeepsUp(t *testing.T) {
	var n int
	p := NewPump(func(int) error { n++; return nil }, 64)
	for i := range 10 {
		p.Send(i)
	}
	if lost := p.Close(time.Second); lost != 0 || n != 10 {
		t.Fatalf("perdidos=%d entregados=%d", lost, n)
	}
}

// Las preferencias del núcleo rigen donde el campo viene en 0 o vacío; lo explícito las ignora.
func TestIngestOptsUsaLasPreferencias(t *testing.T) {
	p := IngestDefaults{RotateMB: 7, RotateMinutes: 15, MaxFiles: 9, Format: "crudo"}
	_, s, err := IngestOpts{Prefs: p}.Build(context.Background(), "/d", "x_{fecha}")
	if err != nil {
		t.Fatal(err)
	}
	if s.RotateBytes != 7<<20 || s.RotateEvery != 15*time.Minute || s.MaxFiles != 9 || s.Format != "crudo" {
		t.Fatalf("sink = %+v", s)
	}
	_, s, err = IngestOpts{Prefs: p, RotateMB: 3, RotateMinutes: 2, MaxFiles: 4, Format: "jsonl"}.Build(context.Background(), "/d", "x_{fecha}")
	if err != nil {
		t.Fatal(err)
	}
	if s.RotateBytes != 3<<20 || s.RotateEvery != 2*time.Minute || s.MaxFiles != 4 || s.Format != "jsonl" {
		t.Fatalf("lo explícito debía ganar: %+v", s)
	}
}

func TestValidateIngestDefaults(t *testing.T) {
	if err := ValidateIngestDefaults(context.Background(), IngestDefaults{}); err != nil {
		t.Fatalf("todo en fábrica es válido: %v", err)
	}
	for _, d := range []IngestDefaults{{RotateMB: 1025}, {RotateMB: -1}, {RotateMinutes: 10081}, {RotateMinutes: -5}, {RotateMinutes: 307445736}, {RotateMinutes: -307445733}, {MaxFiles: 1001}, {MaxFiles: -1}, {Format: "xml"}} {
		if ValidateIngestDefaults(context.Background(), d) == nil {
			t.Errorf("%+v debía rechazarse", d)
		}
	}
	if err := ValidateIngestDefaults(context.Background(), IngestDefaults{RotateMB: 1024, RotateMinutes: 10080, MaxFiles: 1000, Format: "jsonl"}); err != nil {
		t.Fatalf("los topes del rango valen: %v", err)
	}
}
