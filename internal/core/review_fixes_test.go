package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func (h *harness) created(t *testing.T, cred string, sc *v1.Schedule) (string, string) {
	t.Helper()
	s := h.spec(cred)
	if sc != nil {
		s.Schedule = sc
	}
	cj, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
	if err != nil {
		t.Fatal(err)
	}
	lt := h.loginTest(t, cj.JobId)
	return cj.JobId, lt[0].HostKeyFingerprint
}

func TestDoubleArm(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, fp := h.created(t, cred, nil)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}})
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, e := range errs {
		if e == nil {
			ok++
		} else if status.Code(e) != codes.FailedPrecondition {
			t.Fatalf("unexpected error: %v", e)
		}
	}
	if ok != 1 {
		t.Fatalf("successful arms = %d, want 1 (%v)", ok, errs)
	}
	evs := h.waitJob(t, job, "closed")
	for _, e := range evs {
		if e.GetJobStateChanged().GetState() == "cancelled" {
			t.Fatal("job cancelled by the losing arm")
		}
	}
	if taken, released := h.inh.counts(); taken != 1 || released != 1 {
		t.Fatalf("inhibitor taken=%d released=%d", taken, released)
	}
}

func TestFailedArmKeepsTargets(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, fp := h.created(t, cred, nil)
	// Excluir al único equipo falla; después debe poder armarse con él.
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, ExcludedDeviceIds: []string{"sw1"}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}}); err != nil {
		t.Fatalf("re-arm after failure: %v", err)
	}
	h.waitJob(t, job, "closed")
}

func TestStopWithOpenSubscribe(t *testing.T) {
	h := newHarness(t, nil)
	s, err := h.events.Subscribe(context.Background(), &v1.SubscribeRequest{})
	if err != nil {
		t.Fatal(err)
	}
	s.Header()
	done := make(chan struct{})
	go func() { h.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return with an open Subscribe stream")
	}
}

func TestCloseWritesManifest(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, fp := h.created(t, cred, &v1.Schedule{IntervalSeconds: 3600, Rounds: 5})
	h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}})
	time.Sleep(500 * time.Millisecond) // primera ronda
	h.core.Close()
	if m, _ := filepath.Glob(filepath.Join(h.out, "caso-1_*", "manifest.json")); len(m) != 1 {
		t.Fatalf("manifest after Close: %v", m)
	}
}

func TestSkippedRoundAudited(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, fp := h.created(t, cred, &v1.Schedule{IntervalSeconds: 1, Rounds: 2})
	h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}})
	time.Sleep(300 * time.Millisecond)
	h.core.OnSleep()
	var txt string
	for deadline := time.Now().Add(15 * time.Second); !strings.Contains(txt, `"action":"round.skipped"`) && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		txt = h.auditText(t)
	}
	if !strings.Contains(txt, `"action":"round.skipped"`) {
		t.Fatalf("skipped round not audited:\n%s", txt)
	}
	h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job})
	var m []string
	for deadline := time.Now().Add(5 * time.Second); len(m) == 0 && time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		m, _ = filepath.Glob(filepath.Join(h.out, "caso-1_*", "manifest.json"))
	}
	if len(m) == 0 {
		t.Fatal("no manifest")
	}
	b, _ := os.ReadFile(m[0])
	if !strings.Contains(string(b), `"skipped_rounds": [`) {
		t.Fatalf("manifest lacks skipped rounds:\n%s", b)
	}
}

func TestReadOnlyCallsDontResetIdle(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.IdleLock = 300 * time.Millisecond })
	h.ready(t)
	deadline := time.Now().Add(900 * time.Millisecond)
	for time.Now().Before(deadline) {
		h.vault.Status(ctx(t), &v1.StatusRequest{})
		h.patrol.ListJobs(ctx(t), &v1.ListJobsRequest{})
		time.Sleep(50 * time.Millisecond)
	}
	if st := h.core.vaultState(); st != v1.VaultState_VAULT_STATE_LOCKED {
		t.Fatalf("polling kept the vault open: %v", st)
	}
}

func TestResumeWhileCreatingJobs(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	for i := 0; i < 3; i++ {
		job, fp := h.created(t, cred, &v1.Schedule{IntervalSeconds: 3600, Rounds: 2})
		h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}})
	}
	h.core.OnSleep()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: h.spec(cred)})
		}
	}()
	h.vault.Unlock(ctx(t), &v1.UnlockRequest{MasterPassword: []byte("maestra")})
	wg.Wait()
}

func TestArmExcludesByHostport(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	s := h.spec(cred)
	s.Targets = append(s.Targets, &v1.Target{Address: "127.0.0.1", Port: 1, DeviceId: "muerto"})
	cj, _ := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
	lt := h.loginTest(t, cj.JobId)
	fp := ""
	for _, r := range lt {
		if r.HostKeyFingerprint != "" {
			fp = r.HostKeyFingerprint
		}
	}
	// La UI excluye con el target del Login Test (host:puerto).
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: cj.JobId, AcceptedHostKeyFingerprints: []string{fp}, ExcludedDeviceIds: []string{"127.0.0.1:1"}}); err != nil {
		t.Fatalf("exclusion by host:port ignored: %v", err)
	}
	h.waitJob(t, cj.JobId, "closed")
}

func TestCancelCreatedJobMarksCancelled(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	cj, _ := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: h.spec(cred)})
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: cj.JobId}); err != nil {
		t.Fatal(err)
	}
	l, _ := h.patrol.ListJobs(ctx(t), &v1.ListJobsRequest{})
	for _, j := range l.Jobs {
		if j.JobId == cj.JobId && j.State != "cancelled" {
			t.Fatalf("state = %s", j.State)
		}
	}
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: cj.JobId}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("cancelled job armed: %v", err)
	}
}

func TestLoginTestOnlyOnCreatedJob(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, fp := h.created(t, cred, nil)
	h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}})
	s, err := h.patrol.LoginTest(ctx(t), &v1.LoginTestRequest{JobId: job})
	if err == nil {
		_, err = s.Recv()
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("login test on armed job: %v", err)
	}
	h.waitJob(t, job, "closed")
}

// Un trabajo que ya está cerrando (finish corriendo) no se pausa al suspender ni se vuelve a armar al desbloquear:
// rearmar su ventana volvería a dejar la DEK viva para un trabajo terminado.
func TestSuspenderYReanudarIgnoranTrabajosCerrando(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	j := &job{id: "j-cierra", state: "armed", closing: true, Until: time.Now().Add(time.Hour), creds: []string{cred}}
	h.core.mu.Lock()
	h.core.jobs[j.id] = j
	h.core.mu.Unlock()
	h.core.OnSleep()
	h.core.mu.Lock()
	paused := j.paused
	j.paused = true // como si ya estuviera pausado cuando empezó a cerrar
	h.core.mu.Unlock()
	if paused {
		t.Fatal("OnSleep pausó un trabajo que está cerrando")
	}
	if _, err := h.vault.Unlock(ctx(t), &v1.UnlockRequest{MasterPassword: []byte("maestra")}); err != nil { // Unlock llama a resumePaused
		t.Fatal(err)
	}
	if ws := h.core.vault.Windows(); len(ws) != 0 {
		t.Fatalf("resumePaused rearmó la ventana de un trabajo cerrando: %v", ws)
	}
}

// Si el trabajo empieza a cerrar mientras resumePaused rearma su ventana (Arm va sin el candado del núcleo), la
// ventana se retira: no queda la DEK viva para un trabajo terminado.
func TestResumePausedRetiraLaVentanaSiElTrabajoCerroMientrasTanto(t *testing.T) {
	var j *job
	var core atomic.Pointer[Core]
	var armando atomic.Bool
	h := newHarness(t, func(o *Options) {
		o.Now = func() time.Time {
			if c := core.Load(); c != nil && armando.Load() && j != nil {
				c.mu.Lock()
				j.closing = true // finish arrancó justo durante Arm
				c.mu.Unlock()
			}
			return time.Now()
		}
	})
	core.Store(h.core)
	cred := h.ready(t)
	j = &job{id: "j-carrera", state: "armed", paused: true, Until: time.Now().Add(time.Hour), creds: []string{cred}}
	h.core.mu.Lock()
	h.core.jobs[j.id] = j
	h.core.mu.Unlock()
	armando.Store(true)
	h.core.resumePaused()
	armando.Store(false)
	if ws := h.core.vault.Windows(); len(ws) != 0 {
		t.Fatalf("quedó la ventana de un trabajo cerrando: %v", ws)
	}
	if !j.paused {
		t.Fatal("no debía reanudarse")
	}
}
