package ingest

import (
	"sync"
	"testing"
	"time"
)

// reloj es un reloj falso que solo avanza cuando la prueba lo manda.
type reloj struct {
	mu sync.Mutex
	t  time.Time
}

func newReloj() *reloj { return &reloj{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)} }
func (r *reloj) Now() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.t
}
func (r *reloj) Add(d time.Duration) { r.mu.Lock(); r.t = r.t.Add(d); r.mu.Unlock() }

func TestBucketBurstThenRate(t *testing.T) {
	r := newReloj()
	b := newBucket(10, 20, r.Now())
	pass := 0
	for range 100 {
		if b.take(r.Now()) {
			pass++
		}
	}
	if pass != 20 {
		t.Fatalf("la ráfaga debía dejar pasar 20, pasaron %d", pass)
	}
	r.Add(time.Second) // 10 fichas por segundo
	pass = 0
	for range 100 {
		if b.take(r.Now()) {
			pass++
		}
	}
	if pass != 10 {
		t.Fatalf("tras 1 s debían pasar 10, pasaron %d", pass)
	}
	r.Add(time.Hour) // nunca acumula más que la ráfaga
	pass = 0
	for range 100 {
		if b.take(r.Now()) {
			pass++
		}
	}
	if pass != 20 {
		t.Fatalf("el cubo no debe pasar de la ráfaga: %d", pass)
	}
}

func TestLimitsDefaultsAndValidate(t *testing.T) {
	e := Limits{}.Effective()
	if e.PerSource != 100 || e.PerSourceBurst != 200 || e.Global != 1000 || e.GlobalBurst != 2000 || e.Queue != 4096 {
		t.Fatalf("defaults: %+v", e)
	}
	e = Limits{PerSource: 5, Global: 7}.Effective()
	if e.PerSourceBurst != 10 || e.GlobalBurst != 14 {
		t.Fatalf("la ráfaga por defecto es 2x: %+v", e)
	}
	for _, l := range []Limits{{PerSource: -1}, {PerSource: 10001}, {Global: 100001}, {Global: -5}, {Queue: 63}, {Queue: 65537}, {PerSourceBurst: -1}, {GlobalBurst: 1000001}} {
		if l.Validate() == nil {
			t.Errorf("%+v debía rechazarse", l)
		}
	}
	for _, l := range []Limits{{}, {PerSource: 1, Global: 1, Queue: 64}, {PerSource: 10000, Global: 100000, Queue: 65536}} {
		if err := l.Validate(); err != nil {
			t.Errorf("%+v: %v", l, err)
		}
	}
}

func TestLimiterFloodingSourceDoesNotStarveAnother(t *testing.T) {
	r := newReloj()
	l := newLimiter(Limits{PerSource: 10, Global: 1000}.Effective(), r.Now())
	pasa := func(ip string) bool { _, motivo := l.allow(ip, r.Now()); return motivo == "" }
	n := 0
	for range 1000 {
		if pasa("10.0.0.1") {
			n++
		}
	}
	if n != 20 { // ráfaga por origen
		t.Fatalf("el inundador debía quedar en su ráfaga (20), pasaron %d", n)
	}
	for i := range 10 {
		if !pasa("10.0.0.2") {
			t.Fatalf("el origen tranquilo perdió el mensaje %d", i)
		}
	}
}

func TestLimiterGlobalAndReason(t *testing.T) {
	r := newReloj()
	l := newLimiter(Limits{PerSource: 10000, Global: 5, GlobalBurst: 5}.Effective(), r.Now())
	var global int
	for i := range 20 {
		ip := "10.0.0." + string(rune('1'+i%9))
		if _, m := l.allow(ip, r.Now()); m == dropGlobal {
			global++
		}
	}
	if global != 15 {
		t.Fatalf("debían descartarse 15 por tope global, fueron %d", global)
	}
	l = newLimiter(Limits{PerSource: 1, PerSourceBurst: 1, Global: 1000}.Effective(), r.Now())
	l.allow("10.0.0.1", r.Now())
	if k, m := l.allow("10.0.0.1", r.Now()); m != dropOrigen || k != "10.0.0.1" {
		t.Fatalf("motivo = %q clave = %q", m, k)
	}
}

func TestLimiterSourceTableIsBounded(t *testing.T) {
	r := newReloj()
	l := newLimiter(Limits{PerSource: 1, PerSourceBurst: 1, Global: 100000, GlobalBurst: 100000}.Effective(), r.Now())
	for i := range maxSources + 500 {
		l.allow("10.1."+itoa(i/256)+"."+itoa(i%256), r.Now())
	}
	if len(l.per) > maxSources {
		t.Fatalf("tabla de orígenes sin tope: %d", len(l.per))
	}
	// los orígenes nuevos comparten el cubo «otros»
	if k, _ := l.allow("172.16.9.9", r.Now()); k != "otros" {
		t.Fatalf("clave = %q, quería otros", k)
	}
}

func itoa(n int) string {
	return string(rune('0'+n/100%10)) + string(rune('0'+n/10%10)) + string(rune('0'+n%10))
}

func TestDropLogTopAndSince(t *testing.T) {
	r := newReloj()
	d := newDropLog()
	if d.snapshot().Total != 0 || !d.snapshot().Desde.IsZero() {
		t.Fatal("log vacío esperado")
	}
	first := r.Now()
	d.add(dropOrigen, "a", first)
	r.Add(time.Second)
	for range 3 {
		d.add(dropGlobal, "b", r.Now())
	}
	d.add(dropCola, "a", r.Now())
	for i := range 12 { // más de 10 orígenes: solo salen 10, el mayor primero
		d.add(dropCola, "z"+itoa(i), r.Now())
	}
	s := d.snapshot()
	if s.Total != 17 || s.PorOrigen != 1 || s.Global != 3 || s.ColaLlena != 13 || !s.Desde.Equal(first) {
		t.Fatalf("%+v", s)
	}
	if len(s.Top) != 10 || s.Top[0] != (SourceDrops{"b", 3}) || s.Top[1] != (SourceDrops{"a", 2}) {
		t.Fatalf("top = %+v", s.Top)
	}
}

// Revisión: un descarte global no debe gastar también la ficha del origen.
func TestGlobalDropRefundsSourceToken(t *testing.T) {
	r := newReloj()
	l := newLimiter(Limits{PerSource: 1, PerSourceBurst: 3, Global: 1, GlobalBurst: 1}.Effective(), r.Now())
	if _, m := l.allow("10.0.0.1", r.Now()); m != "" {
		t.Fatalf("el primero debía pasar: %q", m)
	}
	for i := range 5 {
		if _, m := l.allow("10.0.0.1", r.Now()); m != dropGlobal {
			t.Fatalf("descarte %d: motivo %q, quería global (la ficha del origen se devuelve)", i, m)
		}
	}
}

func TestLimiterExpiresIdleSources(t *testing.T) {
	r := newReloj()
	l := newLimiter(Limits{PerSource: 1, PerSourceBurst: 1, Global: 100000, GlobalBurst: 100000}.Effective(), r.Now())
	for i := range maxSources {
		l.allow("10.1."+itoa(i/256)+"."+itoa(i%256), r.Now())
	}
	if k, _ := l.allow("172.16.9.9", r.Now()); k != otros {
		t.Fatalf("con la tabla llena y nadie inactivo, la clave era %q", k)
	}
	t0 := r.Now()
	r.Add(30 * time.Second)
	l.allow("172.16.9.8", r.Now()) // dentro del minuto no se vuelve a buscar
	if !l.purged.Equal(t0) {
		t.Fatal("la búsqueda de cubos inactivos debía limitarse a una por minuto")
	}
	r.Add(8*time.Minute + 30*time.Second)
	l.allow("10.1.000.000", r.Now()) // este origen sigue activo
	r.Add(2 * time.Minute)           // los demás llevan 11 min sin mensajes
	if k, m := l.allow("172.16.9.9", r.Now()); k != "172.16.9.9" || m != "" {
		t.Fatalf("tras expirar, el origen nuevo debía tener cubo propio: %q %q", k, m)
	}
	if _, ok := l.per["10.1.000.000"]; !ok {
		t.Fatal("se expiró un origen activo")
	}
	if len(l.per) > 3 {
		t.Fatalf("los inactivos no se expiraron: %d", len(l.per))
	}
}

func TestDropLogKeysAreBounded(t *testing.T) {
	r := newReloj()
	d := newDropLog()
	for i := range maxDropKeys + 500 {
		d.add(dropOrigen, "k"+itoa(i/256)+"."+itoa(i%256), r.Now())
	}
	if len(d.per) > maxDropKeys+1 {
		t.Fatalf("claves de descarte sin tope: %d", len(d.per))
	}
	if d.snapshot().Total != uint64(maxDropKeys+500) {
		t.Fatal("el total debe contar todo")
	}
}
