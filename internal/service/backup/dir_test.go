package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// sinJob es un núcleo que ya quitó el trabajo del historial: Job siempre da NotFound.
type sinJob struct{ *servicetest.Deps }

func (sinJob) Job(context.Context, string) (service.JobInfo, error) {
	return service.JobInfo{}, status.Error(codes.NotFound, "no existe")
}

// corrida arma una carpeta de corrida terminada dentro de Outputs() con su manifest.json.
func corrida(t *testing.T, sd *servicetest.Deps, manifest string) string {
	t.Helper()
	dir := filepath.Join(sd.Out, "run1")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	carpeta(t, dir, "hostname SW1\nntp clock-period 1\n")
	if manifest != "" {
		os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(manifest), 0o600)
	}
	return dir
}

func svcSinJob(t *testing.T) (*backupSvc, *servicetest.Deps) {
	t.Helper()
	sd := servicetest.New(t)
	s := newSvc(sinJob{sd})
	s.quiet = 0
	t.Cleanup(s.close)
	return s, sd
}

func TestCollectPorDirTrasQuitarElJobLlevaElIdDelManifest(t *testing.T) {
	s, sd := svcSinJob(t)
	dir := corrida(t, sd, `{"job_id":"j-quitado","masked":true}`)
	r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{Dir: dir})
	if err != nil || !r.Done || r.Error != "" || !strings.Contains(r.Report.Text, "1 respaldo(s) guardado(s)") {
		t.Fatalf("%+v %v", r, err)
	}
	es, _ := s.store().List("")
	if len(es) != 1 || es[0].Job != "j-quitado" {
		t.Fatalf("Entry.Job: %+v", es)
	}
	if a := sd.AuditText(); !strings.Contains(a, "job=j-quitado ") {
		t.Errorf("auditoría sin el id del manifest: %s", a)
	}
}

func TestCollectPorDirSinIdEnElManifestUsaLaCarpeta(t *testing.T) {
	s, sd := svcSinJob(t)
	dir := corrida(t, sd, `{"masked":true}`)
	if _, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if es, _ := s.store().List(""); len(es) != 1 || es[0].Job != "run1" {
		t.Fatalf("Entry.Job: %+v", es)
	}
}

func TestCollectPorDirRechaza(t *testing.T) {
	s, sd := svcSinJob(t)
	ok := corrida(t, sd, `{"job_id":"j"}`)
	fuera := t.TempDir()
	carpeta(t, fuera, "x\n")
	os.WriteFile(filepath.Join(fuera, "manifest.json"), []byte(`{"job_id":"j"}`), 0o600)
	enlace := filepath.Join(sd.Out, "escape")
	os.Symlink(fuera, enlace)
	sinMan := filepath.Join(sd.Out, "sinman")
	os.MkdirAll(sinMan, 0o700)
	carpeta(t, sinMan, "x\n")
	datos := filepath.Join(sd.S.Inside[0], "run")
	os.MkdirAll(datos, 0o700)
	os.WriteFile(filepath.Join(datos, "manifest.json"), []byte(`{}`), 0o600)
	casos := map[string]struct{ dir, reason string }{
		"relativa":     {"run1", "prefs.outputs.relativa"},
		"punto_punto":  {ok + "/../run1", "prefs.outputs.punto_punto"},
		"inexistente":  {filepath.Join(sd.Out, "nada"), "prefs.outputs.no_existe"},
		"fuera":        {fuera, "backup.err.dir_fuera"},
		"symlink":      {enlace, "backup.err.dir_fuera"},
		"reservada":    {datos, "prefs.outputs.reservada"},
		"home":         {sd.S.Home, "prefs.outputs.reservada"},
		"sin manifest": {sinMan, "backup.err.dir_sin_manifest"},
	}
	for nombre, c := range casos {
		_, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{Dir: c.dir})
		st, _ := status.FromError(err)
		if st.Code() != codes.InvalidArgument || !strings.Contains(err.Error(), c.reason) {
			t.Errorf("%s: %v (se esperaba %s)", nombre, err, c.reason)
		}
	}
	if es, _ := s.store().List(""); len(es) != 0 {
		t.Errorf("un rechazo guardó respaldos: %+v", es)
	}
}

func TestCollectPorDirAceptaUnaRaizDeJobQuitado(t *testing.T) {
	s, sd := svcSinJob(t)
	raiz := t.TempDir()
	if r, err := filepath.EvalSymlinks(raiz); err == nil {
		raiz = r
	}
	if err := service.RecordJobRoot(sd.DB(), raiz); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(raiz, "run1")
	os.MkdirAll(dir, 0o700)
	carpeta(t, dir, "hostname SW1\n")
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"job_id":"j9"}`), 0o600)
	if r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{Dir: dir}); err != nil || !r.Done {
		t.Fatalf("%+v %v", r, err)
	}
}
