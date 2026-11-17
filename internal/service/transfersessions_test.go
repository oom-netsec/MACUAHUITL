package service

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

type fakeProg struct{ b, t atomic.Int64 }

func (f *fakeProg) Bytes() int64 { return f.b.Load() }
func (f *fakeProg) Total() int64 { return f.t.Load() }

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newSess() (*TransferSessions, *fakeClock) {
	c := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	return NewTransferSessions(c.now), c
}

var meta = liveMeta{"tftp", "10.0.0.5:4000", "r1.cfg", "lectura"}

func TestSessionsRingKeeps100(t *testing.T) {
	r, c := newSess()
	s := r.Open("S1")
	for i := 0; i < 105; i++ {
		p := &fakeProg{}
		m := meta
		m.name = fmt.Sprintf("f%03d", i)
		s.start(m, p)
		c.add(time.Second)
		s.finish(p, fileserve.Transfer{Result: "ok"})
	}
	got, _, ok := r.List("S1", "es")
	if !ok || len(got) != 100 {
		t.Fatalf("len=%d ok=%v", len(got), ok)
	}
	if got[0].Name != "f104" || got[99].Name != "f005" { // la más reciente arriba; salieron f000..f004
		t.Fatalf("orden: %s ... %s", got[0].Name, got[99].Name)
	}
}

func TestSessionsOrderActiveFirstOldestFirst(t *testing.T) {
	r, c := newSess()
	s := r.Open("S1")
	a, b, d := &fakeProg{}, &fakeProg{}, &fakeProg{}
	m := meta
	m.name = "viejaActiva"
	s.start(m, a)
	c.add(time.Second)
	m.name = "terminada1"
	s.start(m, b)
	c.add(time.Second)
	s.finish(b, fileserve.Transfer{Result: "ok"})
	m.name = "nuevaActiva"
	s.start(m, d)
	c.add(time.Second)
	m.name = "terminada2"
	e := &fakeProg{}
	s.start(m, e)
	s.finish(e, fileserve.Transfer{Result: "ok"})
	got, _, _ := r.List("", "es")
	var names []string
	for _, x := range got {
		names = append(names, x.Name)
	}
	if strings.Join(names, ",") != "viejaActiva,nuevaActiva,terminada2,terminada1" {
		t.Fatalf("orden %v", names)
	}
}

func TestSessionsClosedServerKeep10MinAndMax8(t *testing.T) {
	r, c := newSess()
	s := r.Open("S0")
	s.Close()
	c.add(10*time.Minute - time.Second)
	if _, _, ok := r.List("S0", "es"); !ok {
		t.Fatal("a los 9:59 debe seguir")
	}
	c.add(time.Second)
	if _, _, ok := r.List("S0", "es"); ok {
		t.Fatal("a los 10:00 debe haber salido")
	}
	for i := 0; i < 10; i++ {
		r.Open(fmt.Sprintf("C%d", i)).Close()
		c.add(time.Second)
	}
	for i := 0; i < 10; i++ {
		_, _, ok := r.List(fmt.Sprintf("C%d", i), "es")
		if want := i >= 2; ok != want {
			t.Fatalf("C%d presente=%v", i, ok)
		}
	}
	if _, _, ok := r.List("nunca", "es"); ok {
		t.Fatal("id desconocido")
	}
}

func TestSessionsRate(t *testing.T) {
	r, c := newSess()
	s := r.Open("S1")
	p := &fakeProg{}
	p.t.Store(1000)
	s.start(meta, p)
	c.add(2 * time.Second)
	p.b.Store(200)
	rate := func() float64 { g, _, _ := r.List("S1", "es"); return g[0].BytesPerSec }
	if v := rate(); v != 100 { // primera lectura: promedio 200 B / 2 s
		t.Fatalf("promedio = %v", v)
	}
	c.add(500 * time.Millisecond)
	p.b.Store(700)
	if v := rate(); v != 100 { // ventana < 1 s: repite
		t.Fatalf("repetida = %v", v)
	}
	c.add(500 * time.Millisecond) // 1 s desde la muestra
	if v := rate(); v != 500 {    // (700-200)/1 s
		t.Fatalf("delta = %v", v)
	}
	c.add(time.Second)
	p.b.Store(1000)
	s.finish(p, fileserve.Transfer{Result: "ok"})
	g, _, _ := r.List("S1", "es")
	if g[0].State != "done" || g[0].BytesPerSec != 1000.0/4 || g[0].Bytes != 1000 || g[0].Total != 1000 { // 4 s desde el inicio
		t.Fatalf("terminada: %+v", g[0])
	}
}

func TestSessionsFailedErrorInRequestLanguage(t *testing.T) {
	r, _ := newSess()
	s := r.Open("S1")
	p := &fakeProg{}
	s.start(meta, p)
	s.finish(p, fileserve.Transfer{Result: "error", Error: "servidor detenido", ReasonT: i18n.Tx("fileserve.reason.stopped")})
	es, _, _ := r.List("S1", "es")
	en, _, _ := r.List("S1", "en")
	if es[0].Error != "servidor detenido" || en[0].Error != "server stopped" || es[0].ErrorCode != "fileserve.reason.stopped" || es[0].State != "failed" {
		t.Fatalf("%+v / %+v", es[0], en[0])
	}
}

func TestSessionsNameSanitized(t *testing.T) {
	r, _ := newSess()
	s := r.Open("S1")
	m := meta
	m.name = "a‮b\x1b[2Jc"
	s.start(m, &fakeProg{})
	g, _, _ := r.List("", "es")
	if g[0].Name != "a?b?[2Jc" {
		t.Fatalf("name = %q", g[0].Name)
	}
}

func rej(client, cause, name string) fileserve.Transfer {
	return fileserve.Transfer{Proto: "tftp", Client: client, File: name, Rejected: true, Cause: cause, Error: "archivo no publicado", ReasonT: i18n.Tx("fileserve.reason.not_published")}
}

func TestSessionsRejectionsGroupedByIPAndCause(t *testing.T) {
	r, c := newSess()
	s := r.Open("S1")
	s.Reject(rej("10.0.0.9:1111", "not_found", "a"))
	c.add(time.Second)
	s.Reject(rej("10.0.0.9:2222", "not_found", "b")) // otro puerto: mismo grupo
	s.Reject(rej("10.0.0.9:2222", "origin_denied", "b"))
	s.Reject(rej("[2001:db8::1]:5", "not_found", "c"))
	got, rs, _ := r.List("S1", "es")
	if len(got) != 0 || len(rs) != 3 {
		t.Fatalf("sesiones=%d grupos=%d", len(got), len(rs))
	}
	var g *struct{ n, f, l int64 }
	for _, x := range rs {
		if x.Ip == "10.0.0.9" && x.Cause == "not_found" {
			g = &struct{ n, f, l int64 }{x.Count, x.First, x.Last}
			if x.Name != "b" || x.ReasonCode != "fileserve.reason.not_published" || x.Protocol != "tftp" || x.ServerId != "S1" {
				t.Fatalf("grupo %+v", x)
			}
		}
		if x.Ip == "2001:db8::1" && x.Count != 1 {
			t.Fatalf("v6 %+v", x)
		}
	}
	if g == nil || g.n != 2 || g.l-g.f != 1000 {
		t.Fatalf("grupo = %+v", g)
	}
}

func TestSessionsRejection33rdEvictsOldest(t *testing.T) {
	r, c := newSess()
	s := r.Open("S1")
	for i := 0; i < 33; i++ {
		s.Reject(rej(fmt.Sprintf("10.0.1.%d:1", i), "not_found", "x"))
		c.add(time.Second)
	}
	_, rs, _ := r.List("S1", "es")
	if len(rs) != 32 {
		t.Fatalf("grupos = %d", len(rs))
	}
	for _, x := range rs {
		if x.Ip == "10.0.1.0" {
			t.Fatal("el más viejo debía salir")
		}
	}
}

func TestSessionsRejectionNameSanitizedAndCut(t *testing.T) {
	r, _ := newSess()
	s := r.Open("S1")
	s.Reject(rej("10.0.0.9:1", "not_found", "\x1b[2J‮"+strings.Repeat("ñ", 300)))
	_, rs, _ := r.List("S1", "es")
	n := []rune(rs[0].Name)
	if len(n) != 128 || strings.ContainsAny(rs[0].Name, "\x1b‮") || !strings.HasPrefix(rs[0].Name, "?[2J?ñ") {
		t.Fatalf("name = %q (%d)", rs[0].Name, len(n))
	}
}

func TestSessionsStrandedClosesAsStopped(t *testing.T) {
	r, c := newSess()
	s := r.Open("S1")
	l := &fileserve.Live{Proto: "tftp", Client: "10.0.0.5:1", File: "r1.cfg", Dir: "lectura"}
	s.Start(l)
	c.add(time.Second)
	st := s.Stranded()
	if len(st) != 1 || st[0].Live != l || st[0].Result != "error" || st[0].ReasonT.Key != "fileserve.reason.stopped" {
		t.Fatalf("%+v", st)
	}
	if id, _ := s.Finish(st[0]); id == "" {
		t.Fatal("sin id")
	}
	g, _, _ := r.List("S1", "en")
	if g[0].State != "failed" || g[0].Error != "server stopped" || len(s.Stranded()) != 0 {
		t.Fatalf("%+v", g[0])
	}
}
