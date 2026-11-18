package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
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
	dir := corrida(t, sd, `{"job_id":"00112233445566ff","masked":true}`)
	r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{Dir: dir})
	if err != nil || !r.Done || r.Error != "" || !strings.Contains(r.Report.Text, "1 respaldo(s) guardado(s)") {
		t.Fatalf("%+v %v", r, err)
	}
	es, _ := s.store().List("")
	if len(es) != 1 || es[0].Job != "00112233445566ff" {
		t.Fatalf("Entry.Job: %+v", es)
	}
	if a := sd.AuditText(); !strings.Contains(a, "job=00112233445566ff ") {
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
		if st.Code() != codes.InvalidArgument || !(strings.Contains(err.Error(), c.reason) || reasonDe(err) == c.reason) {
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

// vivoDeps: el núcleo conoce el trabajo "0123456789abcdef" y ya no conoce ningún otro.
type vivoDeps struct{ *servicetest.Deps }

func (vivoDeps) Job(_ context.Context, id string) (service.JobInfo, error) {
	if id == "0123456789abcdef" {
		return service.JobInfo{State: "armed"}, nil
	}
	return service.JobInfo{}, status.Error(codes.NotFound, "no existe")
}

// Recolectar por carpeta no toca tracked, final ni seen de nadie, ni suelta (forget) un trabajo vivo.
func TestCollectPorDirNoTocaElEstadoDeTrabajosVivos(t *testing.T) {
	sd := servicetest.New(t)
	s := newSvc(vivoDeps{sd})
	s.quiet = 0
	t.Cleanup(s.close)
	s.jobs["run1"] = &tracked{keep: 1} // coincide con la etiqueta de una corrida sin job_id
	s.jobs["0123456789abcdef"] = &tracked{keep: 1}
	dir := corrida(t, sd, `{"job_id":"0123456789abcdef"}`) // un manifest que dice ser el trabajo vivo
	if _, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "manifest.json"))
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{}`), 0o600)
	if _, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{Dir: dir}); err != nil {
		t.Fatal(err)
	}
	if s.jobs["run1"] == nil || s.jobs["0123456789abcdef"] == nil || len(s.final) != 0 || len(s.seen) != 0 || len(s.order) != 0 {
		t.Fatalf("estado tocado: jobs=%v final=%v seen=%v", s.jobs, s.final, s.seen)
	}
}

// Un job_id que es de un trabajo que existe, o que no tiene el formato de NewID, no sirve de etiqueta: se usa la carpeta.
func TestCollectPorDirNoUsaJobIdFalsificado(t *testing.T) {
	for nombre, id := range map[string]string{"existente": "0123456789abcdef", "formato": "../../x", "largo": strings.Repeat("a", 64), "mayusculas": "ABCDEF0123456789"} {
		sd := servicetest.New(t)
		s := newSvc(vivoDeps{sd})
		s.quiet = 0
		dir := corrida(t, sd, `{"job_id":"`+id+`"}`)
		if _, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{Dir: dir}); err != nil {
			t.Fatalf("%s: %v", nombre, err)
		}
		if es, _ := s.store().List(""); len(es) != 1 || es[0].Job != "run1" {
			t.Errorf("%s: Entry.Job: %+v", nombre, es)
		}
		s.close()
	}
}

// Recolectar por id y luego por carpeta una corrida sin job_id no duplica respaldos.
func TestCollectPorIdYLuegoPorDirNoDuplica(t *testing.T) {
	s, sd, _, dir := nuevo(t, "completed")
	carpeta(t, dir, "hostname SW1\nntp clock-period 1\n", "hostname SW1\nvlan 10\n")
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"masked":true}`), 0o600)
	// dir de la corrida dentro de Outputs() para que la acepte CheckRunDir
	run := filepath.Join(sd.Out, "run1")
	os.MkdirAll(run, 0o700)
	carpeta(t, run, "hostname SW1\nntp clock-period 1\n", "hostname SW1\nvlan 10\n")
	os.WriteFile(filepath.Join(run, "manifest.json"), []byte(`{"masked":true}`), 0o600)
	s.d.(jobDeps).info.Dir = run
	if r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"}); err != nil || !strings.Contains(r.Report.Text, "2 respaldo(s) guardado(s)") {
		t.Fatalf("por id: %v %v", r, err)
	}
	r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{Dir: run})
	if err != nil || !strings.Contains(r.Report.Text, "0 respaldo(s) guardado(s), 2 ya existían") {
		t.Fatalf("por dir: %v %v", r, err)
	}
	if es, _ := s.store().List(""); len(es) != 2 {
		t.Errorf("duplicados: %d", len(es))
	}
}

func TestCollectPorDirRechazaCasosBorde(t *testing.T) {
	s, sd := svcSinJob(t)
	ctx := context.Background()
	// dir vacío en CheckRunDir: error, no pánico
	if _, _, err := service.CheckRunDir(ctx, sd, ""); err == nil {
		t.Error("dir vacío debía rechazarse")
	}
	run := corrida(t, sd, "")
	fuera := t.TempDir()
	os.WriteFile(filepath.Join(fuera, "m.json"), []byte(`{"job_id":"j"}`), 0o600)
	os.Symlink(filepath.Join(fuera, "m.json"), filepath.Join(run, "manifest.json"))
	roto := filepath.Join(sd.Out, "roto")
	os.MkdirAll(roto, 0o700)
	os.WriteFile(filepath.Join(roto, "manifest.json"), []byte(`{no es json`), 0o600)
	hermana := filepath.Join(filepath.Dir(sd.Out), "o-hermana", "run")
	os.MkdirAll(hermana, 0o700)
	os.WriteFile(filepath.Join(hermana, "manifest.json"), []byte(`{}`), 0o600)
	for nombre, c := range map[string]struct{ dir, reason string }{
		"manifest symlink": {run, "backup.err.dir_sin_manifest"},
		"json roto":        {roto, "backup.err.dir_sin_manifest"},
		"raíz hermana":     {hermana, "backup.err.dir_fuera"},
	} {
		_, err := s.CollectBackups(ctx, &v1.CollectBackupsRequest{Dir: c.dir})
		if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument || !(strings.Contains(err.Error(), c.reason) || reasonDe(err) == c.reason) {
			t.Errorf("%s: %v (se esperaba %s)", nombre, err, c.reason)
		}
	}
}

// reasonDe es el reason de ErrorInfo del error (el motivo ya no va pegado al texto: 43e-9).
func reasonDe(err error) string {
	for _, d := range status.Convert(err).Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok {
			return ei.Reason
		}
	}
	return ""
}
