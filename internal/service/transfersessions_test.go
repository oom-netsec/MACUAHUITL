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
	s.Reject(rej("10.0.0.9:1", "not_found", "x"))
	s.close()
	c.add(10*time.Minute - time.Second)
	if _, _, ok := r.List("S0", "es"); !ok {
		t.Fatal("a los 9:59 debe seguir")
	}
	c.add(time.Second)
	if _, _, ok := r.List("S0", "es"); ok {
		t.Fatal("a los 10:00 debe haber salido")
	}
	for i := 0; i < 10; i++ {
		cs := r.Open(fmt.Sprintf("C%d", i))
		cs.Reject(rej("10.0.0.9:1", "not_found", "x"))
		cs.close()
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

func TestSessionsShutdownClosesAsStoppedOnce(t *testing.T) {
	r, c := newSess()
	s := r.Open("S1")
	l := &fileserve.Live{Proto: "tftp", Client: "10.0.0.5:1", File: "r1.cfg", Dir: "lectura"}
	s.Start(l)
	c.add(time.Second)
	var got []Stranded
	s.Shutdown(func(x Stranded) { got = append(got, x) })
	if len(got) != 1 || got[0].ID == "" || got[0].T.Live != l || got[0].T.Result != "error" || got[0].T.ReasonT.Key != "fileserve.reason.stopped" {
		t.Fatalf("%+v", got)
	}
	// Un OnTransfer tardío de la misma Live ya no encuentra la sesión: no se cierra ni se audita dos veces.
	if id, _ := s.Finish(got[0].T); id != "" {
		t.Fatalf("Finish dio id %q", id)
	}
	g, _, _ := r.List("S1", "en")
	if len(g) != 1 || g[0].Id != got[0].ID || g[0].State != "failed" || g[0].Error != "server stopped" || g[0].Ended == 0 {
		t.Fatalf("%+v", g)
	}
}

// Un servidor sin sesiones ni rechazos (un bind fallido) no ocupa uno de los 8 cupos de cerrados.
func TestSessionsEmptyServerNotKept(t *testing.T) {
	r, c := newSess()
	keep := r.Open("K")
	keep.Reject(rej("10.0.0.9:1", "not_found", "x"))
	keep.close()
	for i := 0; i < 20; i++ {
		c.add(time.Second)
		r.Open(fmt.Sprintf("vacio%d", i)).Shutdown(func(Stranded) {})
	}
	if _, _, ok := r.List("K", "es"); !ok {
		t.Fatal("el servidor con rechazos debía quedarse")
	}
	if _, _, ok := r.List("vacio19", "es"); ok {
		t.Fatal("un servidor vacío no se conserva")
	}
}

// Lo que mandó el par (mensaje de ERROR, tipo de canal) no llega crudo ni largo a la lista.
func TestSessionsPeerTextSanitizedAndCut(t *testing.T) {
	r, _ := newSess()
	s := r.Open("S1")
	raw := "x\x1b]0;pwn\a\u202e" + strings.Repeat("A", 60000)
	bad := fileserve.Transfer{Error: "el equipo canceló: " + raw, ReasonT: i18n.Tx("fileserve.reason.client_abort_msg", "msg", raw), Result: "error"}
	p := &fakeProg{}
	s.start(meta, p)
	s.finish(p, bad)
	rb := bad
	rb.Rejected, rb.Cause, rb.Client, rb.Proto = true, "other", "10.0.0.9:1", "tftp"
	s.Reject(rb)
	for _, loc := range []string{"es", "en"} {
		g, rs, _ := r.List("S1", loc)
		for _, v := range []string{g[0].Error, rs[0].Reason} {
			if strings.ContainsAny(v, "\x1b\a\u202e") || len([]rune(v)) > 160 {
				t.Fatalf("%s: sin sanear o largo (%d): %q", loc, len([]rune(v)), v)
			}
		}
	}
}

func TestSessionsRejectionIPv4MappedGroupsWithIPv4(t *testing.T) {
	r, _ := newSess()
	s := r.Open("S1")
	s.Reject(rej("10.0.0.9:1", "not_found", "a"))
	s.Reject(rej("[::ffff:10.0.0.9]:2", "not_found", "a"))
	_, rs, _ := r.List("S1", "es")
	if len(rs) != 1 || rs[0].Count != 2 || rs[0].Ip != "10.0.0.9" {
		t.Fatalf("%+v", rs)
	}
}
