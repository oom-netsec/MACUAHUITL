package core

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// quitar llama a RemoveJobs por gRPC.
func (h *harness) quitar(t *testing.T, ids ...string) *v1.RemoveJobsResponse {
	t.Helper()
	r, err := h.patrol.RemoveJobs(ctx(t), &v1.RemoveJobsRequest{JobIds: ids})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// creados crea n trabajos sin armar.
func (h *harness) creados(t *testing.T, cred string, n int) []string {
	t.Helper()
	var ids []string
	for range n {
		id, _ := h.created(t, cred, nil)
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (h *harness) filasJob(t *testing.T, id string) int {
	t.Helper()
	var n int
	if err := h.core.db.QueryRow(`SELECT count(*) FROM jobs WHERE id=?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// ponEstado fuerza el estado en memoria de un trabajo (activo, terminado sin cerrar, etc.).
func (h *harness) ponEstado(id, state string, closed bool) {
	j, _ := h.core.getJob(id)
	h.core.mu.Lock()
	j.state, j.closed = state, closed
	h.core.mu.Unlock()
}

func motivos(r *v1.RemoveJobsResponse) map[string]string {
	m := map[string]string{}
	for _, s := range r.Skipped {
		m[s.JobId] = s.Reason
	}
	return m
}

func TestRemoveJobsIdsDuplicadosEInexistentes(t *testing.T) {
	h := newHarness(t, nil)
	ids := h.creados(t, h.ready(t), 3)
	r := h.quitar(t, ids[1], ids[0], ids[1], "no-existe")
	if r.Removed != 2 || !slices.Equal(r.RemovedIds, ids[:2]) || len(r.Skipped) != 0 {
		t.Fatalf("r = %+v", r)
	}
	for _, id := range ids[:2] {
		if h.filasJob(t, id) != 0 || listar(t, h.core, true)[id] != nil {
			t.Fatalf("%s sigue", id)
		}
	}
	if h.filasJob(t, ids[2]) != 1 {
		t.Fatal("quitó de más")
	}
	if strings.Contains(h.auditText(t), "no-existe") {
		t.Fatal("un inexistente se auditó")
	}
}

func TestRemoveJobsActivoYEnUsoVanASkippedYElRestoSeQuita(t *testing.T) {
	h := newHarness(t, nil)
	ids := h.creados(t, h.ready(t), 6)
	h.ponEstado(ids[0], "armed", false)
	h.ponEstado(ids[1], "arming", false)
	h.ponEstado(ids[2], "completed", false) // B1: en finish, !closed => activo
	h.ponEstado(ids[3], "completed", true)
	h.core.addPinned(func() []service.PinnedJob {
		return []service.PinnedJob{{ID: ids[3], Reason: "change_pre"}, {ID: ids[0], Reason: "backup_import"}}
	})
	r := h.quitar(t, ids...)
	want := map[string]string{ids[0]: "active", ids[1]: "active", ids[2]: "active", ids[3]: "change_pre"}
	got := motivos(r)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("skipped = %v, quería %v", got, want)
	}
	if r.Removed != 2 || !slices.Equal(r.RemovedIds, ids[4:]) {
		t.Fatalf("r = %+v", r)
	}
	// Los saltados no se auditan; los quitados sí.
	a := h.auditText(t)
	for _, id := range ids[:4] {
		if strings.Contains(a, `"action":"job.removed","target":"`+id) {
			t.Fatalf("saltado auditado: %s", id)
		}
	}
	if !strings.Contains(a, `"target":"`+ids[4]+`"`) {
		t.Fatal("quitado sin auditar")
	}
}

func TestRemoveJobsAllFinishedSaltaActivosEnUsoYCreated(t *testing.T) {
	h := newHarness(t, nil)
	ids := h.creados(t, h.ready(t), 5)
	h.ponEstado(ids[0], "completed", true)
	h.ponEstado(ids[1], "cancelled", true)
	h.ponEstado(ids[2], "failed", false) // sin cerrar: activo
	h.ponEstado(ids[3], "completed", true)
	h.core.addPinned(func() []service.PinnedJob { return []service.PinnedJob{{ID: ids[3], Reason: "adhoc_unread"}} })
	r, err := h.patrol.RemoveJobs(ctx(t), &v1.RemoveJobsRequest{AllFinished: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.RemovedIds, ids[:2]) || fmt.Sprint(motivos(r)) != fmt.Sprint(map[string]string{ids[2]: "active", ids[3]: "adhoc_unread"}) {
		t.Fatalf("r = %+v", r)
	}
	if h.filasJob(t, ids[4]) != 1 { // el created no es «terminado»
		t.Fatal("all_finished quitó un created")
	}
	var det string
	for _, e := range h.auditEntries(t) {
		if e.Action == "job.removed" {
			det = e.Detail
		}
	}
	if !strings.Contains(det, "reason=clear_finished") {
		t.Fatalf("detalle = %q", det)
	}
}

func TestRemoveJobsArgumentos(t *testing.T) {
	h := newHarness(t, nil)
	for _, req := range []*v1.RemoveJobsRequest{{}, {JobIds: []string{"x"}, AllFinished: true}} {
		_, err := h.patrol.RemoveJobs(con(t, "en"), req)
		reason, _ := reasonOf(err)
		if status.Code(err) != codes.InvalidArgument || reason != "patrol.err.remove_args" {
			t.Fatalf("%+v: %v", req, err)
		}
	}
	_, err := h.patrol.RemoveJobs(con(t, "es"), &v1.RemoveJobsRequest{})
	if !strings.Contains(status.Convert(err).Message(), "job_ids") {
		t.Fatalf("es: %v", err)
	}
}

func TestRemoveJobsAuditoriaExactaYUnaPorJob(t *testing.T) {
	h := newHarness(t, nil)
	ids := h.creados(t, h.ready(t), 2)
	h.quitar(t, ids...)
	n := 0
	for _, e := range h.auditEntries(t) {
		if e.Action == "job.removed" {
			n++
			want := fmt.Sprintf(`name="caso-1" dir=%q state=created finished= reason=manual`, h.out)
			if e.Detail != want {
				t.Fatalf("detalle %q != %q", e.Detail, want)
			}
		}
	}
	if n != 2 {
		t.Fatalf("job.removed = %d", n)
	}
}

func hashes(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			out[p] = fmt.Sprintf("%x", sha256.Sum256(b))
		}
		return nil
	})
	return out
}

func TestRemoveJobsNoTocaLaEvidenciaEnDisco(t *testing.T) {
	h := newHarness(t, nil)
	job := h.closedJob(t, h.ready(t))
	antes := hashes(t, h.out)
	if len(antes) < 2 {
		t.Fatalf("sin evidencia: %v", antes)
	}
	if r := h.quitar(t, job); r.Removed != 1 {
		t.Fatalf("r = %+v", r)
	}
	if despues := hashes(t, h.out); fmt.Sprint(despues) != fmt.Sprint(antes) {
		t.Fatalf("la evidencia cambió:\n%v\n%v", antes, despues)
	}
}

func TestPersistJobTardioNoResucitaLaFila(t *testing.T) {
	h := newHarness(t, nil)
	id := h.creados(t, h.ready(t), 1)[0]
	j, _ := h.core.getJob(id)
	h.quitar(t, id)
	h.core.persistJob(j)
	if h.filasJob(t, id) != 0 {
		t.Fatal("persistJob resucitó la fila")
	}
}

func TestRemoveJobsGuardaLaRaizParaFleetEInventory(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	raiz := t.TempDir()
	os.Chmod(raiz, 0o700)
	s := h.spec(cred)
	s.OutputDir = raiz
	cj, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
	if err != nil {
		t.Fatal(err)
	}
	h.quitar(t, cj.JobId)
	if got := service.JobOutputRoots(coreDeps{h.core}); !slices.Contains(got, filepath.Clean(raiz)) {
		t.Fatalf("raíces = %v", got)
	}
}

func TestRemoveJobsDeleteFallidoDevuelveElJobAMemoria(t *testing.T) {
	h := newHarness(t, nil)
	id := h.creados(t, h.ready(t), 1)[0]
	j, _ := h.core.getJob(id)
	if _, err := h.core.db.Exec(`DROP TABLE run_devices`); err != nil {
		t.Fatal(err)
	}
	_, err := h.patrol.RemoveJobs(ctx(t), &v1.RemoveJobsRequest{JobIds: []string{id}})
	if status.Code(err) != codes.Internal {
		t.Fatalf("err = %v", err)
	}
	h.core.mu.Lock()
	back, removed := h.core.jobs[id] == j, j.removed
	h.core.mu.Unlock()
	if !back || removed || h.filasJob(t, id) != 1 {
		t.Fatalf("back=%v removed=%v", back, removed)
	}
	if !strings.Contains(h.auditText(t), `"action":"job.remove_failed","target":"`+id+`"`) {
		t.Fatal("sin job.remove_failed")
	}
	h.core.persistJob(j) // sigue guardándose
}

func TestCancelYGetRunDeUnJobQuitadoDanNotFound(t *testing.T) {
	h := newHarness(t, nil)
	id := h.creados(t, h.ready(t), 1)[0]
	h.quitar(t, id)
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: id}); status.Code(err) != codes.NotFound {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := h.patrol.GetRun(ctx(t), &v1.GetRunRequest{JobId: id}); status.Code(err) != codes.NotFound {
		t.Fatalf("getrun: %v", err)
	}
}

// ArmJob tomó el job con getJob y la quita llegó antes de c.mu: ArmJob debe ver removed bajo c.mu.
func TestArmJobConElJobYaQuitadoDaNotFound(t *testing.T) {
	h := newHarness(t, nil)
	id := h.creados(t, h.ready(t), 1)[0]
	j, _ := h.core.getJob(id)
	h.quitar(t, id)
	h.core.mu.Lock()
	h.core.jobs[id] = j // el puntero que ArmJob ya tenía en la mano
	h.core.mu.Unlock()
	_, err := (&patrolSvc{c: h.core}).ArmJob(ctx(t), &v1.ArmJobRequest{JobId: id})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("err = %v", err)
	}
	h.core.mu.Lock()
	st := j.state
	h.core.mu.Unlock()
	if st != "created" {
		t.Fatalf("estado = %s", st)
	}
}

// Quitar y armar a la vez (con -race): gana uno solo, sin tercer caso.
func TestArmJobContraQuitarEnParalelo(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	for i := range 4 {
		id, fp := h.created(t, cred, &v1.Schedule{IntervalSeconds: 1, Rounds: 1})
		var wg sync.WaitGroup
		var armErr, rmErr error
		var rr *v1.RemoveJobsResponse
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, armErr = h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: id, AcceptedHostKeyFingerprints: []string{fp}})
		}()
		go func() {
			defer wg.Done()
			rr, rmErr = h.patrol.RemoveJobs(ctx(t), &v1.RemoveJobsRequest{JobIds: []string{id}})
		}()
		wg.Wait()
		if rmErr != nil {
			t.Fatal(rmErr)
		}
		removed := len(rr.RemovedIds) == 1
		switch {
		case removed && status.Code(armErr) != codes.NotFound:
			t.Fatalf("it %d: quitado pero ArmJob = %v", i, armErr)
		case !removed && (armErr != nil || motivos(rr)[id] != "active"):
			t.Fatalf("it %d: armó pero quita = %+v, arm = %v", i, rr, armErr)
		}
		if removed && h.filasJob(t, id) != 0 {
			t.Fatalf("it %d: fila viva", i)
		}
	}
}

func TestAddPinnedSeConsultaSinTomarElMutexDelNucleo(t *testing.T) {
	h := newHarness(t, nil)
	id := h.creados(t, h.ready(t), 1)[0]
	h.ponEstado(id, "completed", true)
	h.core.addPinned(func() []service.PinnedJob {
		if h.core.mu.TryLock() { // el conjunto «en uso» se calcula antes de c.mu
			h.core.mu.Unlock()
			return nil
		}
		t.Error("c.mu tomado al consultar el conjunto en uso")
		return nil
	})
	done := make(chan struct{})
	go func() { h.quitar(t, id); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("bloqueado")
	}
}

func TestAdhocSinLeerSeFijaYSeLiberaAlLeerlo(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.adhocLote(t, h.ready(t), h.target)
	for deadline := time.Now().Add(20 * time.Second); !h.jobClosed(job); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no cerró")
		}
	}
	if got := motivos(h.quitar(t, job))[job]; got != "adhoc_unread" {
		t.Fatalf("motivo = %q", got)
	}
	ad := v1.NewAdhocServiceClient(h.conn)
	if _, err := ad.AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: job}); err != nil {
		t.Fatal(err)
	}
	if r := h.quitar(t, job); r.Removed != 1 {
		t.Fatalf("tras leer: %+v", r)
	}
}
