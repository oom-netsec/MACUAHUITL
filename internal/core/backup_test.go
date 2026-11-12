package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// backupRun arma un respaldo (primero sin armar para ver la huella de la llave de host).
func (h *harness) backupRun(t *testing.T, cred string, mut func(*v1.StartBackupRequest)) string {
	t.Helper()
	bc := v1.NewBackupServiceClient(h.conn)
	req := &v1.StartBackupRequest{Targets: []*v1.Target{h.target}, CredentialId: cred, Startup: true}
	if mut != nil {
		mut(req)
	}
	r, err := bc.StartBackup(ctx(t), req)
	if err != nil || r.Armed || !strings.Contains(r.Detail, "Login Test") {
		t.Fatalf("start = %+v %v", r, err)
	}
	req.AcceptedHostKeyFingerprints = []string{h.loginTest(t, r.JobId)[0].HostKeyFingerprint}
	if r, err = bc.StartBackup(ctx(t), req); err != nil || !r.Armed {
		t.Fatalf("start = %+v %v", r, err)
	}
	return r.JobId
}

func TestRespaldoDeExtremoAExtremo(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	bc := v1.NewBackupServiceClient(h.conn)
	job := h.backupRun(t, cred, nil)
	var res *v1.CollectBackupsResponse
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		var err error
		if res, err = bc.CollectBackups(ctx(t), &v1.CollectBackupsRequest{JobId: job}); err != nil {
			t.Fatal(err)
		}
		if res.Done {
			break
		}
	}
	if !res.Done || res.Error != "" {
		t.Fatalf("res = %+v", res)
	}
	l, err := bc.ListBackups(ctx(t), &v1.ListBackupsRequest{})
	if err != nil || strings.Count(l.Report.Json, `"kind":"running"`) != 1 || !strings.Contains(l.Report.Json, `"masked":true`) || !strings.Contains(l.Report.Text, "AVISO") {
		t.Fatalf("lista = %v %v", l.GetReport(), err)
	}
	var id string
	for _, f := range strings.Fields(l.Report.Text) {
		if strings.Contains(f, "/") {
			id = f
			break
		}
	}
	g, err := bc.GetBackup(ctx(t), &v1.GetBackupRequest{Id: id})
	if err != nil || !strings.Contains(g.Text, "hostname") {
		t.Fatalf("get = %+v %v", g, err)
	}
	for _, p := range []string{"MARKER-PW", "MARKER-EN"} {
		if strings.Contains(g.Text, p) {
			t.Errorf("el respaldo trae %s", p)
		}
	}
	fi, err := os.Stat(filepath.Join(h.out, "respaldos", id+".cfg"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("archivo: %v %v", fi, err)
	}
	// La carpeta de Patrol se limpió: lo único en respaldos/ es la del equipo y .trabajos vacío.
	if ents, _ := os.ReadDir(filepath.Join(h.out, "respaldos", ".trabajos")); len(ents) != 0 {
		t.Errorf("quedó la carpeta de Patrol: %v", ents)
	}
	// La colecta guarda cada ronda en cuanto la lee, así que backup.save puede quedar antes o después de job.finish.
	audit := h.auditText(t)
	actionsInOrder(t, audit, "backup.start", "job.create", "job.arm", "backup.save")
	actionsInOrder(t, audit, "job.arm", "job.finish")
}

// Programado: el vigilante guarda cada ronda sin que nadie pregunte.
func TestRespaldoProgramadoSeGuardaSolo(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	h.backupRun(t, cred, func(r *v1.StartBackupRequest) { r.Startup, r.IntervalSeconds, r.Rounds, r.Keep = false, 1, 2, 5 })
	bc := v1.NewBackupServiceClient(h.conn)
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		l, err := bc.ListBackups(ctx(t), &v1.ListBackupsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(l.Report.Json, `"kind":"running"`) == 2 {
			return
		}
	}
	t.Fatal("no se guardaron las dos rondas")
}
