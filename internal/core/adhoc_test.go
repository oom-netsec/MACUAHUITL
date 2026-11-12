package core

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func TestAdhocRechazaComandosQueCambianAlgo(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	ad := v1.NewAdhocServiceClient(h.conn)
	for _, cmds := range []string{"configure terminal", "show version\nreload", "show run | redirect flash:x"} {
		_, err := ad.StartAdhoc(ctx(t), &v1.StartAdhocRequest{Targets: []*v1.Target{h.target}, CredentialId: cred, Commands: cmds})
		if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "solo lectura") {
			t.Errorf("%q: %v", cmds, err)
		}
	}
	if l, _ := h.patrol.ListJobs(ctx(t), &v1.ListJobsRequest{}); len(l.Jobs) != 0 {
		t.Fatalf("un lote rechazado no debe crear trabajos: %v", l.Jobs)
	}
	if _, err := ad.StartAdhoc(ctx(t), &v1.StartAdhocRequest{CredentialId: cred, Commands: "show clock"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("sin equipos: %v", err)
	}
	if !strings.Contains(h.auditText(t), `"action":"adhoc.denied"`) {
		t.Error("el rechazo no quedó en la bitácora")
	}
	if _, err := ad.AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: "nope"}); status.Code(err) != codes.NotFound {
		t.Errorf("trabajo inexistente: %v", err)
	}
}

func TestAdhocDeExtremoAExtremo(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	ad := v1.NewAdhocServiceClient(h.conn)
	req := &v1.StartAdhocRequest{Targets: []*v1.Target{h.target}, CredentialId: cred, Commands: "show version\nshow clock\n"}
	// Llave de host nueva: no arma, pero el trabajo queda para revisarlo.
	r, err := ad.StartAdhoc(ctx(t), req)
	if err != nil || r.Armed || r.JobId == "" || !strings.Contains(r.Detail, "Login Test") {
		t.Fatalf("start = %+v %v", r, err)
	}
	if res, err := ad.AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: r.JobId}); err != nil || res.Done {
		t.Fatalf("sin armar no hay resultado: %+v %v", res, err)
	}
	req.AcceptedHostKeyFingerprints = []string{h.loginTest(t, r.JobId)[0].HostKeyFingerprint}
	if r, err = ad.StartAdhoc(ctx(t), req); err != nil || !r.Armed {
		t.Fatalf("start = %+v %v", r, err)
	}
	var res *v1.AdhocResultResponse
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if res, err = ad.AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: r.JobId}); err != nil {
			t.Fatal(err)
		}
		if res.Done {
			break
		}
	}
	if !res.Done || !strings.Contains(res.Report.Json, `"device":"SW-LAB-01"`) || !strings.HasPrefix(res.Csv, "equipo,direccion,comando,estado,salida\n") ||
		!strings.Contains(res.Markdown, "SW-LAB-01") || !strings.Contains(res.Report.Text, "== SW-LAB-01") {
		t.Fatalf("res = %+v", res)
	}
	actionsInOrder(t, h.auditText(t), "adhoc.start", "job.create", "job.arm", "job.finish", "adhoc.result")
}

// adhocLote arma un lote en target (primero sin armar para ver su huella) y espera su resultado.
func (h *harness) adhocLote(t *testing.T, cred string, target *v1.Target) (job string, wait func() *v1.AdhocResultResponse) {
	t.Helper()
	ad := v1.NewAdhocServiceClient(h.conn)
	req := &v1.StartAdhocRequest{Targets: []*v1.Target{target}, CredentialId: cred, Commands: "show clock\n"}
	r, err := ad.StartAdhoc(ctx(t), req)
	if err != nil {
		t.Fatal(err)
	}
	req.AcceptedHostKeyFingerprints = []string{h.loginTest(t, r.JobId)[0].HostKeyFingerprint}
	if r, err = ad.StartAdhoc(ctx(t), req); err != nil || !r.Armed {
		t.Fatalf("start = %+v %v", r, err)
	}
	return r.JobId, func() *v1.AdhocResultResponse {
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			res, err := ad.AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: r.JobId})
			if err != nil {
				t.Fatal(err)
			}
			if res.Done {
				// Done sale en cuanto existe el manifest; finish aún cierra y persiste el estado. Sin esperarlo,
				// un UPDATE de la prueba puede ser pisado por ese persistJob final.
				h.core.watchers.Wait()
				return res
			}
		}
		t.Fatal("el lote no terminó")
		return nil
	}
}

// Dos lotes seguidos (el sello de carpeta es de un segundo) no comparten carpeta ni mezclan equipos.
func TestAdhocDosLotesNoComparten(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	addr, _ := simulator.Start(t, simulator.Config{Hostname: "SW-LAB-02", Username: "admin", Password: "MARKER-PW", Enable: "MARKER-EN", Transcripts: transcripts()})
	ap := netip.MustParseAddrPort(addr)
	t2 := &v1.Target{Address: ap.Addr().String(), Port: uint32(ap.Port()), DeviceId: "sw2"}
	j1, wait1 := h.adhocLote(t, cred, h.target)
	j2, wait2 := h.adhocLote(t, cred, t2)
	r1, r2 := wait1(), wait2()
	if !strings.Contains(r1.Report.Json, "SW-LAB-01") || strings.Contains(r1.Report.Json, "SW-LAB-02") ||
		!strings.Contains(r2.Report.Json, "SW-LAB-02") || strings.Contains(r2.Report.Json, "SW-LAB-01") {
		t.Errorf("informes mezclados:\n%s\n%s", r1.Report.Json, r2.Report.Json)
	}
	d := coreDeps{h.core}
	i1, _ := d.Job(j1)
	i2, _ := d.Job(j2)
	if i1.Dir == "" || i1.Dir == i2.Dir || filepath.Dir(i1.Dir) == filepath.Dir(i2.Dir) {
		t.Errorf("carpetas compartidas: %q %q", i1.Dir, i2.Dir)
	}
}

// Si el cierre del trabajo falla (aquí manifest.json no se puede escribir), el resultado termina con error y no queda en "completed" para siempre.
func TestAdhocCierreFallidoTerminaConError(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	ad := v1.NewAdhocServiceClient(h.conn)
	job, _ := h.adhocLote(t, cred, h.target)
	info, _ := coreDeps{h.core}.Job(job)
	if err := os.Mkdir(filepath.Join(info.Dir, "manifest.json"), 0o700); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		res, err := ad.AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: job})
		if err != nil {
			t.Fatal(err)
		}
		if res.Done {
			if res.Error == "" || res.Report != nil {
				t.Fatalf("res = %+v", res)
			}
			return
		}
	}
	t.Fatal("quedó esperando para siempre")
}

// Tras reiniciar el núcleo el trabajo recargado conserva su carpeta: Corridas, Deriva, Visibilidad y Adhoc la ven.
func TestJobRecargadoConservaSuCarpeta(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, wait := h.adhocLote(t, cred, h.target)
	wait()
	before, _ := coreDeps{h.core}.Job(job)
	if k := h.summary(t, job).Kind; k != "adhoc" {
		t.Fatalf("kind = %q, quería adhoc", k)
	}
	h.restart(t)
	if k := h.summary(t, job).Kind; k != "adhoc" { // el tipo se persiste con el trabajo
		t.Fatalf("kind recargado = %q, quería adhoc", k)
	}
	info, err := coreDeps{h.core}.Job(job)
	if err != nil || info.Dir == "" || info.Dir != before.Dir || info.State != "completed" {
		t.Fatalf("recargado = %+v %v, antes = %+v", info, err, before)
	}
	res, err := v1.NewAdhocServiceClient(h.conn).AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: job})
	if err != nil || !res.Done || res.Error != "" || !strings.Contains(res.Report.Json, `"devices":1`) {
		t.Fatalf("adhoc recargado = %+v %v", res, err)
	}
	if _, err := v1.NewAnalysisServiceClient(h.conn).AnalyzeJob(ctx(t), &v1.AnalyzeJobRequest{Job: job}); err != nil {
		t.Errorf("corridas: %v", err)
	}
	if _, err := v1.NewVisibilityServiceClient(h.conn).BuildTopology(ctx(t), &v1.BuildTopologyRequest{JobId: job}); status.Code(err) == codes.FailedPrecondition {
		t.Errorf("visibilidad: %v", err)
	}
	if _, err := v1.NewDriftServiceClient(h.conn).Drift(ctx(t), &v1.DriftRequest{Job: job}); err != nil && strings.Contains(err.Error(), "aún no tiene salidas") {
		t.Errorf("deriva: %v", err)
	}
}

// Un cierre fallido se recuerda tras reiniciar: el cliente recibe el error en vez de esperar para siempre.
func TestJobRecargadoConCierreFallidoTerminaConError(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.adhocLote(t, cred, h.target)
	info, _ := coreDeps{h.core}.Job(job)
	os.Mkdir(filepath.Join(info.Dir, "manifest.json"), 0o700)
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if i, _ := (coreDeps{h.core}).Job(job); i.FinishErr != "" {
			break
		}
	}
	h.restart(t)
	res, err := v1.NewAdhocServiceClient(h.conn).AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: job})
	if err != nil || !res.Done || res.Error == "" {
		t.Fatalf("res = %+v %v", res, err)
	}
}

// Un trabajo recargado sin carpeta nunca lee la carpeta de trabajo del demonio.
func TestAdhocResultSinCarpetaTerminaConError(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, wait := h.adhocLote(t, cred, h.target)
	wait()
	j, _ := h.core.getJob(job)
	h.core.mu.Lock()
	j.OutputDir, j.writer = "", nil
	h.core.mu.Unlock()
	res, err := v1.NewAdhocServiceClient(h.conn).AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: job})
	if err != nil || !res.Done || res.Error == "" || res.Report != nil {
		t.Fatalf("res = %+v %v", res, err)
	}
}

// Un lote que estaba armado cuando cayó el núcleo vuelve como fallido: el cliente recibe el error y no espera para siempre.
func TestAdhocLoteArmadoAlCaerTerminaConError(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, wait := h.adhocLote(t, cred, h.target)
	wait()
	if _, err := h.core.db.Exec(`UPDATE jobs SET state='armed' WHERE id=?`, job); err != nil {
		t.Fatal(err)
	}
	h.restart(t)
	res, err := v1.NewAdhocServiceClient(h.conn).AdhocResult(ctx(t), &v1.AdhocResultRequest{JobId: job})
	if err != nil || !res.Done || res.Error == "" || res.State != "failed" {
		t.Fatalf("res = %+v %v", res, err)
	}
}
