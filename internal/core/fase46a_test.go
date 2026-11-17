package core

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// reabre cierra el núcleo del harness, siembra filas en la base y abre otro con el reloj dado.
func reabre(t *testing.T, h *harness, now func() time.Time, rows func(exec func(q string, a ...any))) *Core {
	t.Helper()
	p := h.core.p
	h.core.Close()
	db := openDB(t, p)
	rows(func(q string, a ...any) {
		if _, err := db.Exec(q, a...); err != nil {
			t.Fatal(err)
		}
	})
	db.Close()
	c, err := New(p, Options{Actor: "tester", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func listar(t *testing.T, c *Core, past bool) map[string]*v1.JobSummary {
	t.Helper()
	r, err := (&patrolSvc{c: c}).ListJobs(context.Background(), &v1.ListJobsRequest{IncludePast: past})
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]*v1.JobSummary{}
	for _, j := range r.Jobs {
		m[j.JobId] = j
	}
	return m
}

func TestFinishedAtRellenoAlCargar(t *testing.T) {
	h := newHarness(t, nil)
	fin := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	hist, _ := json.Marshal(jobHistory{Phases: []phase{
		{At: fin.Add(-time.Hour), Kind: "JOB_PHASE_KIND_FAILED", Reason: "phase.round_zip_failed"},
		{At: fin, Kind: "JOB_PHASE_KIND_COMPLETED"},
	}})
	ya, _ := json.Marshal(jobHistory{FinishedAt: fin.Add(time.Hour), Phases: []phase{{At: fin, Kind: "JOB_PHASE_KIND_COMPLETED"}}})
	c := reabre(t, h, func() time.Time { return fin.Add(48 * time.Hour) }, func(x func(string, ...any)) {
		const q = `INSERT INTO jobs(id,name,spec_json,state,created_at,history_json) VALUES(?,?,'{"Name":"n"}',?,'2026-03-01T08:00:00Z',?)`
		x(q, "conFase", "n", "completed", string(hist))
		x(q, "sinFase", "n", "cancelled", "{}")
		x(q, "yaTenia", "n", "completed", string(ya))
		x(q, "creado", "n", "created", "{}")
	})
	g := listar(t, c, true)
	if got := g["conFase"].FinishedAt.AsTime(); !got.Equal(fin) {
		t.Fatalf("con fase: %v", got)
	}
	if got := g["sinFase"].FinishedAt.AsTime(); !got.Equal(time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("sin fase usa created_at: %v", got)
	}
	if got := g["yaTenia"].FinishedAt.AsTime(); !got.Equal(fin.Add(time.Hour)) {
		t.Fatalf("no se sobrescribe: %v", got)
	}
	if g["creado"].FinishedAt != nil || g["creado"].Past {
		t.Fatalf("created lleva finished_at: %+v", g["creado"])
	}
}

func TestArmedCaidoPasaAFailedConFinishedAtDelArranque(t *testing.T) {
	h := newHarness(t, nil)
	now := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	c := reabre(t, h, func() time.Time { return now }, func(x func(string, ...any)) {
		x(`INSERT INTO jobs(id,name,spec_json,state,created_at) VALUES('caido','c','{"Name":"c"}','armed','2026-01-01T00:00:00Z')`)
	})
	j := listar(t, c, true)["caido"]
	if j.State != "failed" || !j.FinishedAt.AsTime().Equal(now) || j.Past {
		t.Fatalf("caido = %+v", j)
	}
}

func TestFinishedAtSeFijaUnaVezYPorEstado(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	id, _ := h.created(t, cred, nil)
	j, _ := h.core.getJob(id)
	set := func(st string) { h.core.mu.Lock(); j.state = st; h.core.mu.Unlock() }
	fin := func() time.Time { h.core.mu.Lock(); defer h.core.mu.Unlock(); return j.FinishedAt }
	// B2: una FAILED de zip de ronda o de close_failed con el job aún en curso o cerrándose no fija nada.
	set("armed")
	h.core.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_FAILED, 1, "phase.round_zip_failed", nil)
	set("arming")
	h.core.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_FAILED, 0, "phase.close_failed", nil)
	if !fin().IsZero() {
		t.Fatalf("finished_at fijado por una fase FAILED con el job en curso: %v", fin())
	}
	set("completed")
	h.core.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_COMPLETED, 0, "", nil)
	primero := fin()
	if primero.IsZero() {
		t.Fatal("finished_at sin fijar al terminar")
	}
	time.Sleep(2 * time.Millisecond)
	h.core.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_PACKAGED, 0, "", nil)
	if !fin().Equal(primero) {
		t.Fatal("finished_at cambió")
	}
	// persistJob lo guarda y sobrevive al reinicio.
	h.core.persistJob(j)
	c := reabre2(t, h)
	if got := listar(t, c, true)[id].FinishedAt.AsTime(); !got.Equal(primero.Truncate(0).UTC()) && got.Sub(primero).Abs() > time.Microsecond {
		t.Fatalf("recargado %v != %v", got, primero)
	}
}

func reabre2(t *testing.T, h *harness) *Core {
	t.Helper()
	return reabre(t, h, nil, func(func(string, ...any)) {})
}

// El orden real: finish y closeCancelled ponen el estado terminal antes de la fase final.
func TestFinishFijaFinishedAtConLaFaseFinal(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.arm(t, cred)
	h.waitJob(t, job, "closed")
	s := h.summary(t, job)
	last := s.Phases[len(s.Phases)-1]
	if last.Kind != v1.JobPhaseKind_JOB_PHASE_KIND_COMPLETED || !s.FinishedAt.AsTime().Equal(last.At.AsTime()) {
		t.Fatalf("finished_at=%v última=%v %v", s.FinishedAt, last.Kind, last.At)
	}
	id, _ := h.created(t, cred, nil)
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: id}); err != nil {
		t.Fatal(err)
	}
	c := h.summary(t, id)
	if c.State != "cancelled" || c.FinishedAt == nil {
		t.Fatalf("cancelado antes de armar: %+v", c)
	}
}

func TestIsPast(t *testing.T) {
	chi, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Skip("sin tzdata")
	}
	d := func(l *time.Location, y int, m time.Month, dd, h, mi int) time.Time {
		return time.Date(y, m, dd, h, mi, 0, 0, l)
	}
	for _, c := range []struct {
		name     string
		fin, now time.Time
		want     bool
	}{
		{"mismo día", d(chi, 2026, 3, 5, 0, 0), d(chi, 2026, 3, 5, 23, 59), false},
		{"23:59 y 00:00 del día siguiente", d(chi, 2026, 3, 5, 23, 59), d(chi, 2026, 3, 6, 0, 0), true},
		{"menos de 24 h pero otro día", d(chi, 2026, 3, 5, 22, 0), d(chi, 2026, 3, 6, 1, 0), true},
		{"más de 24 h pero mismo día", d(chi, 2026, 3, 5, 0, 1), d(chi, 2026, 3, 5, 23, 59), false},
		{"fin guardado en UTC, día local anterior", d(time.UTC, 2026, 3, 6, 3, 0), d(chi, 2026, 3, 6, 20, 0), true},
		// DST de EE.UU. (regla anterior a 2022: sigue en vigor en Chicago): 2019-03-10 tiene 23 h, 2019-11-03 tiene 25.
		{"día de 23 h: ayer", d(chi, 2019, 3, 9, 23, 30), d(chi, 2019, 3, 10, 0, 10), true},
		{"día de 23 h: hoy", d(chi, 2019, 3, 10, 0, 10), d(chi, 2019, 3, 10, 23, 50), false},
		{"día de 25 h: hoy", d(chi, 2019, 11, 3, 0, 10), d(chi, 2019, 11, 3, 23, 50), false},
		{"día de 25 h: ayer", d(chi, 2019, 11, 2, 23, 50), d(chi, 2019, 11, 3, 0, 10), true},
		{"reloj hacia atrás: fin futuro", d(chi, 2026, 3, 7, 10, 0), d(chi, 2026, 3, 5, 10, 0), false},
		{"sin fin", time.Time{}, d(chi, 2026, 3, 5, 10, 0), false},
	} {
		if got := isPast(c.fin, c.now); got != c.want {
			t.Errorf("%s: isPast = %v", c.name, got)
		}
	}
}

func TestListJobsConYSinIncludePast(t *testing.T) {
	h := newHarness(t, nil)
	now := time.Date(2026, 6, 10, 15, 0, 0, 0, time.Local)
	hist := func(fin time.Time) string {
		b, _ := json.Marshal(jobHistory{FinishedAt: fin})
		return string(b)
	}
	c := reabre(t, h, func() time.Time { return now }, func(x func(string, ...any)) {
		const q = `INSERT INTO jobs(id,name,spec_json,state,created_at,history_json) VALUES(?,'n','{"Name":"n"}',?,'2026-06-01T00:00:00Z',?)`
		x(q, "hoy", "completed", hist(now.Add(-2*time.Hour)))
		x(q, "ayer", "failed", hist(time.Date(2026, 6, 9, 23, 0, 0, 0, time.Local)))
		x(q, "nuevo", "created", "{}")
	})
	sin := listar(t, c, false)
	if len(sin) != 2 || sin["hoy"] == nil || sin["nuevo"] == nil || sin["hoy"].Past {
		t.Fatalf("sin include_past: %v", sin)
	}
	con := listar(t, c, true)
	if len(con) != 3 || !con["ayer"].Past || con["ayer"].FinishedAt == nil {
		t.Fatalf("con include_past: %v", con)
	}
}
