package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

var ahora46d = time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

// siembra46d abre un núcleo (reloj fijo) con filas ya guardadas: id → (estado, finished_at; cero = sin finished_at), creadas en created.
func siembra46d(t *testing.T, h *harness, now func() time.Time, filas map[string][2]any, created time.Time) *Core {
	t.Helper()
	return reabre(t, h, now, func(x func(string, ...any)) {
		for id, f := range filas {
			hist, _ := json.Marshal(jobHistory{FinishedAt: f[1].(time.Time)})
			x(`INSERT INTO jobs(id,name,spec_json,state,created_at,history_json) VALUES(?,'n','{"Name":"n"}',?,?,?)`,
				id, f[0], created.UTC().Format(time.RFC3339), string(hist))
		}
	})
}

func (c *Core) hay46d(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.jobs[id]
	return ok
}

func cuentaAudit(t *testing.T, c *Core, accion string) int {
	t.Helper()
	var n int
	if err := c.db.QueryRow(`SELECT count(*) FROM audit_log WHERE action=?`, accion).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestPodaEsExactamenteSieteDias(t *testing.T) {
	h := newHarness(t, nil)
	c := siembra46d(t, h, func() time.Time { return ahora46d }, map[string][2]any{
		"seis":  {"completed", ahora46d.Add(-jobRetention + time.Minute)}, // 6 d 23 h 59 min
		"siete": {"failed", ahora46d.Add(-jobRetention)},
		"ocho":  {"cancelled", ahora46d.Add(-jobRetention - time.Hour)},
	}, ahora46d.Add(-100*24*time.Hour))
	if n := c.pruneJobs(); n != 2 {
		t.Fatalf("podó %d", n)
	}
	if !c.hay46d("seis") || c.hay46d("siete") || c.hay46d("ocho") {
		t.Fatal("poda mal")
	}
	if got := cuentaAudit(t, c, "job.pruned"); got != 2 {
		t.Fatalf("job.pruned = %d", got)
	}
}

func TestPodaCreatedSeCuentaDesdeCreatedAt(t *testing.T) {
	h := newHarness(t, nil)
	mk := func(creado time.Time) *Core {
		return siembra46d(t, h, func() time.Time { return ahora46d }, map[string][2]any{"c": {"created", time.Time{}}}, creado)
	}
	c := mk(ahora46d.Add(-jobRetention + time.Minute))
	if c.pruneJobs() != 0 || !c.hay46d("c") {
		t.Fatal("podó un created de 6 d 23 h")
	}
	c.Close()
	c = reabre(t, h, func() time.Time { return ahora46d.Add(time.Minute) }, func(func(string, ...any)) {})
	if c.pruneJobs() != 1 || c.hay46d("c") {
		t.Fatal("no podó un created de 7 d")
	}
}

func TestPodaNoTocaActivosNiAbiertosNiEnUso(t *testing.T) {
	h := newHarness(t, nil)
	viejo := ahora46d.Add(-30 * 24 * time.Hour)
	c := siembra46d(t, h, func() time.Time { return ahora46d }, map[string][2]any{
		"activo": {"completed", viejo}, "uso": {"completed", viejo}, "ok": {"completed", viejo},
	}, viejo)
	c.mu.Lock()
	c.jobs["activo"].closed = false // terminado sin cerrar = activo
	c.mu.Unlock()
	c.addPinned(func() []service.PinnedJob { return []service.PinnedJob{{ID: "uso", Reason: "change_pre"}} })
	if n := c.pruneJobs(); n != 1 {
		t.Fatalf("podó %d", n)
	}
	if !c.hay46d("activo") || !c.hay46d("uso") || c.hay46d("ok") {
		t.Fatal("poda mal")
	}
}

func TestPodaTrasApagadoDe30DiasUnaPasadaUnaTxYUnAuditPorJob(t *testing.T) {
	h := newHarness(t, nil)
	viejo := ahora46d.Add(-30 * 24 * time.Hour)
	filas := map[string][2]any{}
	for i := range 5 {
		filas[fmt.Sprintf("j%d", i)] = [2]any{"completed", viejo}
	}
	c := siembra46d(t, h, func() time.Time { return ahora46d }, filas, viejo)
	// Una sola tx: si el DELETE del último falla, no se borra ninguno.
	if _, err := c.db.Exec(`CREATE TRIGGER falla BEFORE DELETE ON jobs WHEN old.id='j4' BEGIN SELECT RAISE(ABORT,'no'); END`); err != nil {
		t.Fatal(err)
	}
	if c.pruneJobs() != 0 {
		t.Fatal("podó con la tx fallida")
	}
	var n int
	c.db.QueryRow(`SELECT count(*) FROM jobs`).Scan(&n)
	if n != 5 || cuentaAudit(t, c, "job.pruned") != 0 {
		t.Fatalf("filas=%d: la tx no fue única", n)
	}
	c.db.Exec(`DROP TRIGGER falla`)
	if got := c.pruneJobs(); got != 5 {
		t.Fatalf("podó %d", got)
	}
	c.db.QueryRow(`SELECT count(*) FROM jobs`).Scan(&n)
	if n != 0 || cuentaAudit(t, c, "job.pruned") != 5 {
		t.Fatalf("filas=%d pruned=%d", n, cuentaAudit(t, c, "job.pruned"))
	}
	// Auditado después de la tx: la última entrada job.pruned va tras todos los DELETE (una sola conexión: no hay otra forma).
	if got := c.pruneJobs(); got != 0 { // idempotente
		t.Fatalf("segunda pasada podó %d", got)
	}
	if cuentaAudit(t, c, "job.pruned") != 5 {
		t.Fatal("la segunda pasada auditó")
	}
}

func TestPodaSobreviveAReinicioEntrePasadas(t *testing.T) {
	h := newHarness(t, nil)
	viejo := ahora46d.Add(-8 * 24 * time.Hour)
	c := siembra46d(t, h, func() time.Time { return ahora46d }, map[string][2]any{
		"a": {"completed", viejo}, "b": {"completed", ahora46d.Add(-6 * 24 * time.Hour)},
	}, viejo)
	c.pruneJobs()
	c.Close()
	c2 := reabre(t, h, func() time.Time { return ahora46d.Add(25 * time.Hour) }, func(func(string, ...any)) {})
	if c2.hay46d("a") || !c2.hay46d("b") {
		t.Fatal("el reinicio resucitó o perdió jobs")
	}
	if c2.pruneJobs() != 1 || c2.hay46d("b") {
		t.Fatal("la pasada tras el reinicio no podó b")
	}
}

func serve46d(t *testing.T, c *Core) {
	t.Helper()
	sock, _ := os.MkdirTemp("", "mcc")
	t.Cleanup(func() { os.RemoveAll(sock) })
	l, err := ipc.Listen(ipctest.Addr(sock))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Serve(ctx, l); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func TestLaPrimeraPasadaNoCorreEnNewSinoAlArrancarServe(t *testing.T) {
	h := newHarness(t, nil)
	viejo := ahora46d.Add(-30 * 24 * time.Hour)
	c := siembra46d(t, h, func() time.Time { return ahora46d }, map[string][2]any{"a": {"completed", viejo}}, viejo)
	time.Sleep(100 * time.Millisecond)
	if !c.hay46d("a") {
		t.Fatal("New podó")
	}
	serve46d(t, c)
	for i := 0; c.hay46d("a"); i++ {
		if i > 200 {
			t.Fatal("Serve no podó en el tick inmediato")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestCloseEsperaLaPasadaAntesDeCerrarLaBase(t *testing.T) {
	h := newHarness(t, nil)
	viejo := ahora46d.Add(-30 * 24 * time.Hour)
	c := siembra46d(t, h, func() time.Time { return ahora46d }, map[string][2]any{"a": {"completed", viejo}}, viejo)
	var errOut bytes.Buffer
	c.o.ErrOut = &errOut
	entro, suelta := make(chan struct{}), make(chan struct{})
	var once sync.Once
	c.addPinned(func() []service.PinnedJob { // se consulta en medio de la pasada
		once.Do(func() { close(entro); <-suelta })
		return nil
	})
	serve46d(t, c)
	select {
	case <-entro:
	case <-time.After(5 * time.Second):
		t.Fatal("la pasada no arrancó")
	}
	cerrado := make(chan struct{})
	go func() { c.Close(); close(cerrado) }()
	select {
	case <-cerrado:
		t.Fatal("Close no esperó la pasada en curso")
	case <-time.After(300 * time.Millisecond):
	}
	close(suelta)
	select {
	case <-cerrado:
	case <-time.After(10 * time.Second):
		t.Fatal("Close no volvió")
	}
	if errOut.Len() != 0 {
		t.Fatalf("la pasada tocó la base cerrada: %s", errOut.String())
	}
	db := openDB(t, c.p)
	defer db.Close()
	var n int
	db.QueryRow(`SELECT count(*) FROM jobs`).Scan(&n)
	var p int
	db.QueryRow(`SELECT count(*) FROM audit_log WHERE action='job.pruned'`).Scan(&p)
	if n != 0 || p != 1 || strings.Contains(errOut.String(), "closed") {
		t.Fatalf("jobs=%d pruned=%d", n, p)
	}
}
