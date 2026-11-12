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
	want := []string{"CREATED", "LOGIN_TEST_DONE 0 correctos, 1 con fallas", "LOGIN_TEST_DONE 1 correcto, 0 con fallas", "ARMED 1 equipo",
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
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if s = h.summary(t, job); s.DevicesOk == 1 {
			break
		}
	}
	if s.Round != 1 || s.NextRoundAt == nil || time.Until(s.NextRoundAt.AsTime()) < 29*time.Minute {
		t.Fatalf("summary = %+v", s)
	}
	h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job})
	h.waitJob(t, job, "closed")
	s = h.summary(t, job)
	if last := s.Phases[len(s.Phases)-1]; last.Kind != v1.JobPhaseKind_JOB_PHASE_KIND_CANCELLED || s.NextRoundAt != nil {
		t.Fatalf("fases = %v next=%v", phaseLines(s.Phases), s.NextRoundAt)
	}
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
		h.core.addPhase(j, v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_SKIPPED, i+1, "")
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
