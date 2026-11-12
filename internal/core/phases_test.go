package core

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/engine"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
	"github.com/oom-netsec/MACUAHUITL/internal/store"
)

func openDB(t *testing.T, p Paths) *sql.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(p.Data, "macuahuitl.db"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func (h *harness) summary(t *testing.T, job string) *v1.JobSummary {
	t.Helper()
	r, err := h.patrol.ListJobs(ctx(t), &v1.ListJobsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range r.Jobs {
		if j.JobId == job {
			return j
		}
	}
	t.Fatalf("trabajo %s no listado", job)
	return nil
}

func phaseLine(p *v1.JobPhase) string {
	s := strings.TrimPrefix(p.Kind.String(), "JOB_PHASE_KIND_")
	if p.Round > 0 {
		s += fmt.Sprintf(" r%d", p.Round)
	}
	if p.Detail != "" && !strings.HasPrefix(p.Detail, "/") {
		s += " " + p.Detail
	}
	return s
}

func phaseLines(ps []*v1.JobPhase) []string {
	var out []string
	for _, p := range ps {
		if p.At == nil {
			out = append(out, "sin hora")
		}
		out = append(out, phaseLine(p))
	}
	return out
}

func TestJobSummaryAndPhases(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	before := time.Now()
	job, _ := h.arm(t, cred)
	evs := h.waitJob(t, job, "closed")
	s := h.summary(t, job)
	if s.State != "completed" || s.Round != 2 || s.Rounds != 2 || s.DevicesTotal != 1 || s.DevicesOk != 1 || s.DevicesFailed != 0 {
		t.Fatalf("summary = %+v", s)
	}
	if s.ArmedAt == nil || s.ArmedAt.AsTime().Before(before.Add(-time.Second)) || s.WindowEndsAt.AsTime().Sub(s.ArmedAt.AsTime()).Round(time.Second) != time.Hour {
		t.Fatalf("armed_at=%v window_ends_at=%v", s.ArmedAt, s.WindowEndsAt)
	}
	if !strings.Contains(s.OutputDir, "caso-1_") || s.NextRoundAt != nil {
		t.Fatalf("output_dir=%q next=%v", s.OutputDir, s.NextRoundAt)
	}
	want := []string{"CREATED", "LOGIN_TEST_DONE 0 correctos, 1 con fallas", "ARM_CHECK_DONE 1 correcto, 0 con fallas", "ARMED 1 equipo",
		"ROUND_STARTED r1", "ROUND_FINISHED r1 1 correcto, 0 con fallas", "ROUND_STARTED r2", "ROUND_FINISHED r2 1 correcto, 0 con fallas",
		"PACKAGED", "COMPLETED 2 rondas"}
	if got := strings.Join(phaseLines(s.Phases), "|"); got != strings.Join(want, "|") {
		t.Fatalf("fases:\n%s\nwant:\n%s", got, strings.Join(want, "|"))
	}
	if p := s.Phases[8]; !strings.HasSuffix(p.Detail, ".zip") {
		t.Fatalf("PACKAGED sin zip: %q", p.Detail)
	}
	// Las fases también salen en vivo por Subscribe.
	var live []string
	for _, e := range evs {
		if p := e.GetPhaseAdded(); p != nil {
			live = append(live, phaseLine(p))
		}
	}
	if len(live) < 2 || live[len(live)-1] != "COMPLETED 2 rondas" {
		t.Fatalf("fases en vivo = %v", live)
	}
}

func TestNextRoundAndCancelPhase(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, fp := h.created(t, cred, &v1.Schedule{IntervalSeconds: 1800, Rounds: 3}) // la ventana es de 1 h: cabe la segunda ronda
	if s := h.summary(t, job); s.ArmedAt != nil || s.Round != 0 || s.Rounds != 3 || s.OutputDir != h.out {
		t.Fatalf("antes de armar = %+v", s)
	}
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}}); err != nil {
		t.Fatal(err)
	}
	var s *v1.JobSummary
	// Con la máquina cargada la primera ronda tarda: se espera por estado, no por un plazo corto.
	s = h.summaryUntil(t, job, func(s *v1.JobSummary) bool { return s.DevicesOk == 1 })
	if s.Round != 1 || s.NextRoundAt == nil || time.Until(s.NextRoundAt.AsTime()) < 29*time.Minute {
		t.Fatalf("summary = %+v", s)
	}
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job}); err != nil {
		t.Fatal(err)
	}
	// Suscribirse después de cancelar perdía el "closed" si el trabajo cerraba antes: se lee el resumen.
	s = h.summaryUntil(t, job, func(s *v1.JobSummary) bool {
		return len(s.Phases) > 0 && s.Phases[len(s.Phases)-1].Kind == v1.JobPhaseKind_JOB_PHASE_KIND_CANCELLED
	})
	if s.NextRoundAt != nil {
		t.Fatalf("fases = %v next=%v", phaseLines(s.Phases), s.NextRoundAt)
	}
}

// summaryUntil relee el resumen hasta que ok se cumple; falla con el último visto a los 60 s.
func (h *harness) summaryUntil(t *testing.T, job string, ok func(*v1.JobSummary) bool) *v1.JobSummary {
	t.Helper()
	var s *v1.JobSummary
	for deadline := time.Now().Add(60 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if s = h.summary(t, job); ok(s) {
			return s
		}
	}
	t.Fatalf("summary = %+v fases = %v", s, phaseLines(s.Phases))
	return nil
}

func TestPhasesPersistAcrossRestart(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.arm(t, cred)
	h.waitJob(t, job, "closed")
	want := h.summary(t, job)
	created, _ := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: h.spec(cred)})
	p := h.core.p
	h.core.Close()
	// Trabajos guardados antes del historial (sin history_json) y uno que quedó armado al caer el núcleo.
	db := openDB(t, p)
	db.Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at) VALUES('viejo','v','{"Name":"v"}','completed','2026-01-01T00:00:00Z')`)
	db.Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at) VALUES('caido','c','{"Name":"c"}','armed','2026-01-01T00:00:00Z')`)
	db.Exec(`INSERT INTO jobs(id,name,spec_json,state,created_at) VALUES('armando','a','{"Name":"a"}','arming','2026-01-01T00:00:00Z')`)
	db.Close()
	c, err := New(p, Options{Actor: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := (&patrolSvc{c: c}).ListJobs(context.Background(), &v1.ListJobsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*v1.JobSummary{}
	for _, j := range r.Jobs {
		got[j.JobId] = j
	}
	g := got[job]
	if g == nil || g.State != "completed" || g.Round != 2 || g.DevicesOk != 1 || g.OutputDir != want.OutputDir ||
		!g.ArmedAt.AsTime().Equal(want.ArmedAt.AsTime()) || strings.Join(phaseLines(g.Phases), "|") != strings.Join(phaseLines(want.Phases), "|") {
		t.Fatalf("recargado = %+v\nantes = %+v", g, want)
	}
	if v := got["viejo"]; v == nil || v.State != "completed" || len(v.Phases) != 0 {
		t.Fatalf("viejo = %+v", v)
	}
	if v := got["caido"]; v == nil || v.State != "failed" || len(v.Phases) != 1 || v.Phases[0].Kind != v1.JobPhaseKind_JOB_PHASE_KIND_FAILED {
		t.Fatalf("caido = %+v", v)
	}
	if v := got["armando"]; v == nil || v.State != "failed" {
		t.Fatalf("armando = %+v", v) // armado o armándose al caer: nunca vuelve como armable
	}
	if v := got[created.JobId]; v == nil || v.State != "created" || len(v.Phases) != 1 {
		t.Fatalf("creado = %+v", v)
	}
}

func TestPhasesCapped(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.created(t, cred, nil)
	j, _ := h.core.getJob(job)
	for i := 0; i < maxPhases+50; i++ {
		h.core.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_SKIPPED, i+1, "", nil)
	}
	s := h.summary(t, job)
	if len(s.Phases) != maxPhases || s.Phases[len(s.Phases)-1].Round != uint32(maxPhases+50) {
		t.Fatalf("fases = %d, última ronda %d", len(s.Phases), s.Phases[len(s.Phases)-1].Round)
	}
}

// Dos persistencias del mismo trabajo en desorden (el Login Test que termina mientras se cancela) no deben dejar
// en la base un estado más viejo que el de memoria.
func TestPersistJobConcurrenteNoRetrocede(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.created(t, cred, nil)
	j, _ := h.core.getJob(job)
	for i := 0; i < 300; i++ {
		var wg sync.WaitGroup
		for _, st := range []string{"created", "cancelled"} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h.core.mu.Lock()
				j.state = st
				h.core.mu.Unlock()
				h.core.persistJob(j)
			}()
		}
		wg.Wait()
		var db string
		h.core.db.QueryRow(`SELECT state FROM jobs WHERE id = ?`, job).Scan(&db)
		h.core.mu.Lock()
		mem := j.state
		h.core.mu.Unlock()
		if db != mem {
			t.Fatalf("vuelta %d: base = %q, memoria = %q", i, db, mem)
		}
	}
}

// GetRun manda el puerto efectivo: 0 en la spec (el de omisión) sale como 22.
func TestGetRunPuertoEfectivo(t *testing.T) {
	h := newHarness(t, nil)
	j := &job{id: "j-puerto", state: "completed", results: map[int][]patrol.DeviceResult{1: {
		{Target: patrol.Target{Address: "192.168.3.2", Port: 0, DeviceID: "a"}, State: "completed"},
		{Target: patrol.Target{Address: "192.168.3.3", Port: 2222, DeviceID: "b"}, State: "completed"},
	}}}
	h.core.mu.Lock()
	h.core.jobs[j.id] = j
	h.core.mu.Unlock()
	run, err := h.patrol.GetRun(ctx(t), &v1.GetRunRequest{JobId: j.id, Round: 1})
	if err != nil || len(run.Devices) != 2 {
		t.Fatalf("run = %+v %v", run, err)
	}
	if p := run.Devices[0].Target.Port; p != 22 {
		t.Fatalf("puerto 0 salió como %d, quería 22", p)
	}
	if p := run.Devices[1].Target.Port; p != 2222 {
		t.Fatalf("puerto 2222 salió como %d", p)
	}
}

// En: el detalle de cada fase sale traducido y toda fase con detalle lleva su reason y sus args; en es, el
// detalle es el de siempre (lo fija TestJobSummaryAndPhases).
func TestPhasesIdiomaYCodigos(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.arm(t, cred)
	h.waitJob(t, job, "closed")
	list := func(lang string) *v1.JobSummary {
		r, err := h.patrol.ListJobs(con(t, lang), &v1.ListJobsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, j := range r.Jobs {
			if j.JobId == job {
				return j
			}
		}
		t.Fatal("sin trabajo")
		return nil
	}
	en := strings.Join(phaseLines(list("en").Phases), "|")
	want := "CREATED|LOGIN_TEST_DONE 0 successful, 1 failed|ARM_CHECK_DONE 1 successful, 0 failed|ARMED 1 device|ROUND_STARTED r1|ROUND_FINISHED r1 1 successful, 0 failed|ROUND_STARTED r2|ROUND_FINISHED r2 1 successful, 0 failed|PACKAGED|COMPLETED 2 rounds"
	if en != want {
		t.Fatalf("en:\n%s\nquiero:\n%s", en, want)
	}
	if es, sin := strings.Join(phaseLines(list("es").Phases), "|"), strings.Join(phaseLines(list("").Phases), "|"); es != sin || !strings.Contains(es, "1 correcto, 0 con fallas") {
		t.Fatalf("es y sin metadato deben ser iguales y en español:\n%s\n%s", es, sin)
	}
	byKind := map[v1.JobPhaseKind]*v1.JobPhase{}
	for _, p := range list("en").Phases {
		byKind[p.Kind] = p
	}
	if p := byKind[v1.JobPhaseKind_JOB_PHASE_KIND_ARMED]; p.Reason != "phase.devices" || p.Args["n"] != "1" {
		t.Fatalf("ARMED: %+v", p)
	}
	if p := byKind[v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_FINISHED]; p.Reason != "phase.ok_failed" || p.Args["ok"] != "1" || p.Args["failed"] != "0" {
		t.Fatalf("ROUND_FINISHED: %+v", p)
	}
	if p := byKind[v1.JobPhaseKind_JOB_PHASE_KIND_COMPLETED]; p.Reason != "phase.rounds" || p.Args["n"] != "2" {
		t.Fatalf("COMPLETED: %+v", p)
	}
	if p := byKind[v1.JobPhaseKind_JOB_PHASE_KIND_CREATED]; p.Reason != "" || len(p.Args) != 0 {
		t.Fatalf("CREATED no lleva detalle: %+v", p)
	}
	// En vivo: la conversión del evento respeta el idioma.
	ev := eventToProto("en", engine.Event{Kind: engine.Phase, State: "JOB_PHASE_KIND_COMPLETED", Detail: "3 rondas", Reason: "phase.rounds", Args: map[string]string{"n": "3"}})
	if p := ev.GetPhaseAdded(); p.Detail != "3 rounds" || p.Reason != "phase.rounds" {
		t.Fatalf("evento en: %+v", p)
	}
	if p := eventToProto("es", engine.Event{Kind: engine.Phase, State: "JOB_PHASE_KIND_COMPLETED", Detail: "3 rondas", Reason: "phase.rounds", Args: map[string]string{"n": "3"}}).GetPhaseAdded(); p.Detail != "3 rondas" {
		t.Fatalf("evento es: %+v", p)
	}
}
