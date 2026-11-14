package backup

import (
	"context"
	"fmt"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/backup"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

type jobDeps struct {
	*servicetest.Deps
	info *service.JobInfo
}

func (d jobDeps) Job(context.Context, string) (service.JobInfo, error) { return *d.info, nil }

// carpeta arma la salida de Patrol de un equipo con dos rondas.
func carpeta(t *testing.T, dir string, cfgs ...string) {
	t.Helper()
	d := filepath.Join(dir, "SW1_192.0.2.1")
	os.MkdirAll(d, 0o755)
	for i, c := range cfgs {
		hh := 10 + i
		hdr := "===== 2026-11-06T" + itoa(hh) + ":00:00Z · show version =====\nCisco IOS XE\nProcessor board ID FOC0001A0AA\n" +
			"===== 2026-11-06T" + itoa(hh) + ":00:01Z · show running-config =====\n"
		st := "===== 2026-11-06T" + itoa(hh) + ":00:02Z · show startup-config · comando inválido =====\n% Invalid input\n"
		name := "r00" + itoa(i+1) + "_20261106-" + itoa(hh) + "0000.txt"
		os.WriteFile(filepath.Join(d, name), []byte(hdr+c+st), 0o600)
	}
}

func itoa(n int) string { return string(rune('0'+n/10)) + string(rune('0'+n%10)) }

func nuevo(t *testing.T, state string) (*backupSvc, *servicetest.Deps, *service.JobInfo, string) {
	t.Helper()
	sd := servicetest.New(t)
	dir := t.TempDir()
	info := &service.JobInfo{State: state, Dir: dir}
	s := newSvc(jobDeps{sd, info})
	s.quiet = 0 // los archivos de prueba se escriben justo antes de recolectar
	t.Cleanup(s.close)
	return s, sd, info, dir
}

func TestCollectGuardaConPermisosYEsIdempotente(t *testing.T) {
	s, sd, _, dir := nuevo(t, "completed")
	carpeta(t, dir, "hostname SW1\nntp clock-period 1\n", "hostname SW1\nntp clock-period 2\nvlan 10\n")
	r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil || !r.Done || r.Error != "" || !strings.Contains(r.Report.Text, "2 respaldo(s) guardado(s)") {
		t.Fatalf("%+v %v", r, err)
	}
	if !strings.Contains(r.Report.Text, "no devolvió startup-config") {
		t.Errorf("sin aviso de startup: %s", r.Report.Text)
	}
	root := filepath.Join(sd.Out, "respaldos", "SW1_192.0.2.1")
	ents, _ := os.ReadDir(root)
	if len(ents) != 4 { // 2 .cfg + 2 .json
		t.Fatalf("archivos: %v", ents)
	}
	for _, e := range ents {
		if fi, _ := e.Info(); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s = %v", e.Name(), fi.Mode().Perm())
		}
	}
	r, _ = s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
	if !strings.Contains(r.Report.Text, "0 respaldo(s) guardado(s), 2 ya existían") {
		t.Errorf("segunda vez: %s", r.Report.Text)
	}
	if a := sd.AuditText(); !strings.Contains(a, `"action":"backup.save"`) || strings.Contains(a, "hostname SW1") {
		t.Errorf("auditoría: %s", a)
	}
}

func TestCollectAplicaLaRetencionYBorraLaCarpetaDePatrolPropia(t *testing.T) {
	s, sd, info, _ := nuevo(t, "completed")
	lote := filepath.Join(sd.Out, "respaldos", trabajos, "lote-1")
	pj := filepath.Join(lote, "respaldo_20261106-100000")
	os.MkdirAll(pj, 0o700)
	info.Dir = pj
	carpeta(t, pj, "a\n", "b\n")
	s.jobs["j1"] = &tracked{masked: false, keep: 1, lote: lote}
	r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil || !strings.Contains(r.Report.Text, "1 borrado(s) por retención") {
		t.Fatalf("%v %s", err, r.GetReport().GetText())
	}
	if _, err := os.Stat(lote); err == nil {
		t.Error("la carpeta de Patrol sigue")
	}
	l, _ := s.ListBackups(context.Background(), &v1.ListBackupsRequest{Device: "SW1_192.0.2.1"})
	if strings.Count(l.Report.Json, `"id"`) != 1 || strings.Contains(l.Report.Text, "AVISO") || !strings.Contains(l.Report.Json, `"masked":false`) {
		t.Errorf("lista: %s", l.Report.Json)
	}
}

func TestCollectSinTerminarNoEsFinalYAvisaDelEnmascarado(t *testing.T) {
	s, _, info, dir := nuevo(t, "running")
	if r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"}); err != nil || r.Done {
		t.Fatalf("sin salidas aún: %+v %v", r, err)
	}
	carpeta(t, dir, "hostname SW1\n")
	r, _ := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
	if r.Done || !strings.Contains(r.Report.Text, "1 respaldo(s) guardado(s)") {
		t.Fatalf("%+v", r)
	}
	l, _ := s.ListBackups(context.Background(), &v1.ListBackupsRequest{})
	if !strings.Contains(l.Report.Text, "enmascarado") || !strings.Contains(l.Report.Text, "AVISO: ") {
		t.Errorf("sin aviso de enmascarado: %s", l.Report.Text)
	}
	// Terminal sin salidas: termina con error y no se queda esperando.
	info.State, info.Dir, info.FinishErr = "completed", t.TempDir(), "disco lleno"
	if r, _ = s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"}); !r.Done || r.Error != "disco lleno" {
		t.Errorf("%+v", r)
	}
}

func TestListaYGetRechazanNombresMalos(t *testing.T) {
	s, _, _, _ := nuevo(t, "completed")
	ctx := context.Background()
	if _, err := s.ListBackups(ctx, &v1.ListBackupsRequest{Device: "../.."}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("list ..: %v", err)
	}
	for _, id := range []string{"../../etc/passwd", "SW1/../x", "SW1/20261106T100000Z-running"} {
		if _, err := s.GetBackup(ctx, &v1.GetBackupRequest{Id: id}); status.Code(err) != codes.NotFound {
			t.Errorf("get %q: %v", id, err)
		}
	}
}

func TestDiffEntreRespaldos(t *testing.T) {
	s, sd, _, dir := nuevo(t, "completed")
	carpeta(t, dir, "hostname SW1\nntp clock-period 1\ninterface Gi1/0/1\n description PC-01\n", "hostname SW1\nntp clock-period 2\ninterface Gi1/0/1\n description PC-02\n")
	ctx := context.Background()
	s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	a, b := "SW1_192.0.2.1/20261106T100001Z-running", "SW1_192.0.2.1/20261106T110001Z-running"
	r, err := s.DiffBackups(ctx, &v1.DiffBackupsRequest{From: a, To: b})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"+ description PC-02", "- description PC-01", "ignoradas por volátiles: ntp clock-period", "AVISO"} {
		if !strings.Contains(r.Report.Text, want) {
			t.Errorf("falta %q:\n%s", want, r.Report.Text)
		}
	}
	if strings.Contains(r.Report.Text, "+ ntp clock-period") || !strings.Contains(r.Report.Json, `"masked":true`) {
		t.Errorf("volátil o masked: %s", r.Report.Json)
	}
	if _, err := s.DiffBackups(ctx, &v1.DiffBackupsRequest{From: a, To: "SW1_192.0.2.1/20261106T110001Z-startup"}); err == nil {
		t.Error("tipos distintos aceptados")
	}
	if !strings.Contains(sd.AuditText(), `"action":"backup.diff"`) {
		t.Error("el diff no quedó auditado")
	}
	g, err := s.GetBackup(ctx, &v1.GetBackupRequest{Id: a})
	if err != nil || !strings.Contains(g.Text, "PC-01") || !strings.Contains(sd.AuditText(), `"action":"backup.export"`) {
		t.Errorf("get: %v %+v", err, g)
	}
}

func TestStartBackupValidaAntesDeCrearNada(t *testing.T) {
	s, sd, _, _ := nuevo(t, "completed")
	ctx := context.Background()
	if _, err := s.StartBackup(ctx, &v1.StartBackupRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("sin equipos: %v", err)
	}
	tg := []*v1.Target{{Address: "192.0.2.1"}}
	if _, err := s.StartBackup(ctx, &v1.StartBackupRequest{Targets: tg, IntervalSeconds: 60, Rounds: 1}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("intervalo sin rondas: %v", err)
	}
	if _, err := s.StartBackup(ctx, &v1.StartBackupRequest{Targets: tg, Keep: 5000}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("retención enorme: %v", err)
	}
	if _, err := os.Stat(filepath.Join(sd.Out, "respaldos", trabajos)); err == nil {
		t.Error("se creó una carpeta de trabajos aunque la petición era inválida")
	}
}

const dev = "SW1_192.0.2.1"

// trabajoPropio arma un trabajo del servicio con su lote de Patrol y devuelve la carpeta de salida de Patrol.
func trabajoPropio(t *testing.T, s *backupSvc, sd *servicetest.Deps, info *service.JobInfo, keep int) (lote, pj string) {
	t.Helper()
	lote = filepath.Join(sd.Out, "respaldos", trabajos, "lote-1")
	pj = filepath.Join(lote, "respaldo_20261106-100000")
	os.MkdirAll(pj, 0o700)
	info.Dir = pj
	at := func(h, m int) time.Time { return time.Date(2026, 11, 6, h, m, 0, 0, time.UTC) }
	s.jobs["j1"] = &tracked{masked: false, keep: keep, lote: lote, from: at(9, 59), until: at(12, 0)}
	return lote, pj
}

func guardaViejos(t *testing.T, s *backupSvc) {
	t.Helper()
	for i := 0; i < 3; i++ {
		at := time.Date(2026, 11, 6, 8, 10*i, 0, 0, time.UTC)
		if _, _, err := s.store().Save(backup.Entry{Device: dev, Kind: backup.Running, At: at, Job: "viejo"}, fmt.Sprintf("viejo %d\n", i)); err != nil {
			t.Fatal(err)
		}
	}
}

func ids(t *testing.T, s *backupSvc) string {
	t.Helper()
	es, _ := s.store().List(dev)
	var b strings.Builder
	for _, e := range es {
		b.WriteString(e.ID + " ")
	}
	return b.String()
}

// Un banner del equipo con cabeceras falsas (de otra ronda, con fecha 2099) no crea respaldos ni
// hace que la retención borre los reales.
func TestCabecerasFalsasFueraDeLaVentanaNoCreanRespaldos(t *testing.T) {
	s, sd, info, _ := nuevo(t, "completed")
	lote, pj := trabajoPropio(t, s, sd, info, 3)
	guardaViejos(t, s)
	var sb strings.Builder
	sb.WriteString("===== 2026-11-06T10:00:01Z · show running-config =====\nhostname SW1\nbanner motd ^C\n")
	for i := 0; i < 30; i++ {
		fmt.Fprintf(&sb, "===== ronda %d · 2099-01-%02dT00:00:00Z · show running-config =====\nfalso\n", i+2, i+1)
	}
	os.MkdirAll(filepath.Join(pj, dev), 0o755)
	os.WriteFile(filepath.Join(pj, dev, "r001_20261106-100000.txt"), []byte(sb.String()), 0o600)
	r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil {
		t.Fatal(err)
	}
	got := ids(t, s)
	if strings.Contains(got, "2099") || !strings.Contains(got, "20261106T100001Z-running") || !strings.Contains(got, "20261106T082000Z-running") || strings.Count(got, "-running") != 3 {
		t.Errorf("respaldos tras la retención: %s", got)
	}
	if !strings.Contains(r.Report.Text, "fuera de la ventana") {
		t.Errorf("sin aviso de ventana: %s", r.Report.Text)
	}
	if _, err := os.Stat(lote); err != nil {
		t.Error("se borró la carpeta de Patrol aunque hubo secciones ajenas")
	}
}

// Dos secciones del mismo equipo, ronda y tipo no se aceptan: no hay cuál es la real.
func TestSeccionesDuplicadasSeDescartan(t *testing.T) {
	s, sd, info, _ := nuevo(t, "completed")
	lote, pj := trabajoPropio(t, s, sd, info, 3)
	guardaViejos(t, s)
	txt := "===== 2026-11-06T10:00:01Z · show running-config =====\nhostname SW1\n" +
		"===== 2026-11-06T10:30:00Z · show running-config =====\nfalso\n"
	os.MkdirAll(filepath.Join(pj, dev), 0o755)
	os.WriteFile(filepath.Join(pj, dev, "r001_20261106-100000.txt"), []byte(txt), 0o600)
	r, _ := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
	if got := ids(t, s); strings.Count(got, "-running") != 3 || strings.Contains(got, "T100001Z") || strings.Contains(got, "T103000Z") {
		t.Errorf("respaldos: %s", got)
	}
	if !strings.Contains(r.Report.Text, "más de una sección") {
		t.Errorf("sin aviso: %s", r.Report.Text)
	}
	if _, err := os.Stat(lote); err != nil {
		t.Error("se borró la carpeta de Patrol")
	}
}

// Un aviso de tope o de recorte cuenta como fallo: la carpeta de Patrol queda como única copia.
func TestAvisoDeTopeORecorteConservaLaCarpetaDePatrol(t *testing.T) {
	for nombre, lim := range map[string][2]int64{"total": {1 << 20, 120}, "recorte": {60, 1 << 20}} {
		s, sd, info, _ := nuevo(t, "completed")
		lote, pj := trabajoPropio(t, s, sd, info, 3)
		carpeta(t, pj, strings.Repeat("hostname SW1\n", 20))
		restore := analyze.SetLimits(lim[0], lim[1])
		r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
		restore()
		if err != nil || !r.Done {
			t.Fatalf("%s: %+v %v", nombre, r, err)
		}
		if _, err := os.Stat(lote); err != nil {
			t.Errorf("%s: se borró la carpeta de Patrol con avisos: %s", nombre, r.Report.Text)
		}
		if !strings.Contains(r.Report.Text, "Aviso:") {
			t.Errorf("%s: sin aviso: %s", nombre, r.Report.Text)
		}
		if a := sd.AuditText(); !strings.Contains(a, `"action":"backup.warning"`) {
			t.Errorf("%s: el aviso no quedó auditado: %s", nombre, a)
		} else if strings.Contains(a, "recortad") || strings.Contains(a, "sin firma") || strings.Contains(a, "no devolvió") {
			t.Errorf("%s: la auditoría va en inglés: %s", nombre, a)
		}
	}
}

// El vigilante no relee las rondas ya importadas: un archivo ilegible ya importado no genera avisos.
func TestNoRelaLasRondasYaImportadas(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root lee todo")
	}
	s, sd, info, _ := nuevo(t, "running")
	lote, pj := trabajoPropio(t, s, sd, info, 5)
	carpeta(t, pj, "hostname SW1\nuno\n")
	ctx := context.Background()
	r, _ := s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if len(r.Report.Text) == 0 || !strings.Contains(r.Report.Text, "1 respaldo(s) guardado(s)") {
		t.Fatalf("primera: %s", r.Report.Text)
	}
	r1 := filepath.Join(pj, dev, "r001_20261106-100000.txt")
	os.Chmod(r1, 0)
	t.Cleanup(func() { os.Chmod(r1, 0o600) })
	r, err := s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil || strings.Contains(r.Report.Text, "Aviso") || r.Done {
		t.Fatalf("segunda releyó el archivo: %v %s", err, r.GetReport().GetText())
	}
	// Termina el trabajo sin archivos nuevos: sigue siendo limpio y borra el lote.
	info.State = "completed"
	if r, _ = s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"}); !r.Done || r.Error != "" {
		t.Fatalf("final: %+v", r)
	}
	if _, err := os.Stat(lote); err == nil {
		t.Error("la carpeta de Patrol sigue")
	}
}

// Fase 16c: restaurar solo confía en una ficha firmada con la llave de la bóveda, del mismo equipo (serie) y completa.
func fichas(t *testing.T, s *backupSvc) []backup.Entry {
	t.Helper()
	es, err := s.store().List("SW1_192.0.2.1")
	if err != nil || len(es) == 0 {
		t.Fatalf("sin respaldos: %v", err)
	}
	return es
}

func TestCollectFirmaLaFichaConLaLlaveDeLaBovedaYGuardaLaSerie(t *testing.T) {
	s, sd, _, dir := nuevo(t, "completed")
	v := sd.CreateVault()
	carpeta(t, dir, "hostname SW1\nend\n")
	if _, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"}); err != nil {
		t.Fatal(err)
	}
	key, err := service.BackupKey(v, false)
	if err != nil {
		t.Fatalf("la llave se crea al guardar: %v", err)
	}
	e := fichas(t, s)[0]
	if e.Serial != "FOC0001A0AA" || e.Truncated || !e.Verify(key) {
		t.Errorf("serie, recorte y firma de la ficha: %+v", e)
	}
	if strings.Contains(sd.AuditText(), string(key)) {
		t.Error("la llave no va a la bitácora")
	}
}

func TestCollectSinBovedaGuardaSinFirmaYLoDice(t *testing.T) {
	s, _, _, dir := nuevo(t, "completed")
	carpeta(t, dir, "hostname SW1\nend\n")
	r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil || !strings.Contains(r.Report.Text, "sin firma") {
		t.Fatalf("debe avisar que quedó sin firma (no se podrá restaurar): %v %s", err, r.GetReport().GetText())
	}
	if e := fichas(t, s)[0]; e.Sig != "" || e.Serial != "FOC0001A0AA" {
		t.Errorf("sin bóveda abierta no hay firma, pero sí serie: %+v", e)
	}
}

func TestCollectMarcaElRespaldoRecortado(t *testing.T) {
	s, sd, _, dir := nuevo(t, "completed")
	sd.CreateVault()
	carpeta(t, dir, strings.Repeat("hostname SW1\n", 20)+"end\n")
	restore := analyze.SetLimits(60, 1<<20)
	_, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
	restore()
	if err != nil {
		t.Fatal(err)
	}
	if e := fichas(t, s)[0]; !e.Truncated {
		t.Errorf("la salida recortada queda marcada en la ficha: %+v", e)
	}
}

// El informe final cuenta lo que guardó el trabajo entero, no solo la última llamada: el vigilante o un Collect anterior ya pudo guardar rondas.
func TestElInformeFinalCuentaLoGuardadoPorLlamadasAnteriores(t *testing.T) {
	s, sd, info, _ := nuevo(t, "running")
	_, pj := trabajoPropio(t, s, sd, info, 5)
	ctx := context.Background()
	carpeta(t, pj, "hostname SW1\nuno\n")
	r, err := s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil || r.Done || !strings.Contains(r.Report.Text, "1 respaldo(s) guardado(s)") {
		t.Fatalf("antes de completed: %v %+v", err, r)
	}
	carpeta(t, pj, "hostname SW1\nuno\n", "hostname SW1\ndos\n")
	info.State = "completed"
	r, err = s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil || !r.Done || !strings.Contains(r.Report.Text, "2 respaldo(s) guardado(s)") {
		t.Fatalf("el final debe contar las dos rondas: %v %s", err, r.GetReport().GetText())
	}
	if strings.Count(r.Report.Json, "-running") != 2 {
		t.Errorf("el JSON final lista los dos respaldos: %s", r.Report.Json)
	}
}

// patrolFalso deja crear un trabajo (guardando su spec) y falla al armarlo, para que StartBackup devuelva sin vigilante.
type patrolFalso struct {
	v1.UnimplementedPatrolServiceServer
	spec *v1.JobSpec
}

func (p *patrolFalso) CreateJob(_ context.Context, r *v1.CreateJobRequest) (*v1.CreateJobResponse, error) {
	p.spec = r.Spec
	return &v1.CreateJobResponse{JobId: "j1"}, nil
}

func (p *patrolFalso) ArmJob(context.Context, *v1.ArmJobRequest) (*v1.ArmJobResponse, error) {
	return nil, status.Error(codes.FailedPrecondition, "sin armar")
}

type conPatrol struct {
	jobDeps
	p v1.PatrolServiceServer
}

func (d conPatrol) Patrol() v1.PatrolServiceServer { return d.p }

// Si la carpeta de salidas cambia a mitad de un respaldo, todo queda en la carpeta con que arrancó (los respaldos
// y el lote temporal, que puede traer salida cruda) y el lote se borra al terminar.
func TestCambiarLaCarpetaAMitadDeUnRespaldoNoPartePorLaMitad(t *testing.T) {
	sd := servicetest.New(t)
	vieja := sd.Outputs()
	info := &service.JobInfo{State: "running"}
	fp := &patrolFalso{}
	s := newSvc(conPatrol{jobDeps{sd, info}, fp})
	t.Cleanup(s.close)
	if _, err := s.StartBackup(context.Background(), &v1.StartBackupRequest{Targets: []*v1.Target{{Address: "192.0.2.1"}}, IntervalSeconds: 60, Rounds: 2}); err != nil {
		t.Fatal(err)
	}
	if fp.spec.Kind != "backup" {
		t.Fatalf("kind = %q, quería backup", fp.spec.Kind)
	}
	lote := fp.spec.OutputDir
	if !strings.HasPrefix(lote, vieja) {
		t.Fatalf("lote = %s", lote)
	}
	nueva := filepath.Join(t.TempDir(), "nueva")
	sd.S.Apply(nueva, service.IngestDefaults{}) // cambia con el respaldo en curso
	pj := filepath.Join(lote, "respaldo_20261106-100000")
	os.MkdirAll(pj, 0o700)
	info.Dir = pj
	carpeta(t, pj, "hostname SW1\nuno\n")
	// el trabajo se crea "ahora": la ventana de las secciones de prueba (2026-11-06) se ajusta al reloj de la prueba
	s.jobs["j1"].from, s.jobs["j1"].until = time.Date(2026, 11, 6, 9, 59, 0, 0, time.UTC), time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	if r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"}); err != nil || r.Done {
		t.Fatalf("ronda 1: %+v %v", r, err)
	}
	carpeta(t, pj, "hostname SW1\nuno\n", "hostname SW1\ndos\n")
	info.State = "completed"
	if r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"}); err != nil || !r.Done || r.Error != "" {
		t.Fatalf("final: %+v %v", r, err)
	}
	es, _ := backup.Store{Root: filepath.Join(vieja, "respaldos")}.List(dev)
	if len(es) != 2 {
		t.Fatalf("los dos respaldos debían quedar en la carpeta vieja: %v", es)
	}
	if _, err := os.Stat(filepath.Join(nueva, "respaldos")); err == nil {
		t.Error("el respaldo escribió en la carpeta nueva")
	}
	if _, err := os.Stat(lote); err == nil {
		t.Error("el lote temporal no se borró")
	}
}

// Fase 30d: si los avisos y sus textos se desparejan, el informe en inglés no mezcla un aviso con la traducción de otro.
func TestCollectedTextNuncaMezclaAvisos(t *testing.T) {
	c := collected{Warnings: []string{"uno", "dos"}, WarningTexts: []i18n.Text{i18n.Tx("backup.warn.unsigned")}}
	if got := c.text("en"); !strings.Contains(got, "uno") || !strings.Contains(got, "dos") || strings.Contains(got, "signature") {
		t.Errorf("mezcló avisos: %q", got)
	}
	c = collected{}
	c.warn(i18n.Tx("backup.warn.unsigned"))
	if en := c.text("en"); !strings.Contains(en, "without a signature") {
		t.Errorf("pareados: %q", en)
	}
}

type jobFalla struct{ *servicetest.Deps }

func (jobFalla) Job(ctx context.Context, id string) (service.JobInfo, error) {
	return service.JobInfo{}, service.Err(ctx, codes.NotFound, "patrol.err.job_missing", i18n.A("id", id))
}

// Fase 30e: en el respaldo programado el error de Deps.Job ya es status; la auditoría backup.failed sale en inglés.
func TestRespaldoProgramadoAuditaElFalloEnIngles(t *testing.T) {
	sd := servicetest.New(t)
	s := newSvc(jobFalla{sd})
	s.poll = time.Millisecond
	t.Cleanup(s.close)
	s.watch("j9")
	s.wg.Wait()
	if got := sd.AuditText(); !strings.Contains(got, "backup.failed") || !strings.Contains(got, "job j9 does not exist") {
		t.Fatalf("auditoría: %s", got)
	}
}

// La salida parcial de un comando cortado (« · incompleto») no se guarda como respaldo y conserva la carpeta de Patrol.
func TestSeccionIncompletaNoSeGuardaComoRespaldo(t *testing.T) {
	s, sd, info, _ := nuevo(t, "completed")
	lote, pj := trabajoPropio(t, s, sd, info, 3)
	os.MkdirAll(filepath.Join(pj, dev), 0o755)
	txt := "===== 2026-11-06T10:00:01Z · show running-config · incompleto =====\nhostname SW1\n"
	os.WriteFile(filepath.Join(pj, dev, "r001_20261106-100000.txt"), []byte(txt), 0o600)
	r, err := s.CollectBackups(context.Background(), &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(t, s); strings.Contains(got, "-running") {
		t.Errorf("se guardó una salida incompleta: %s", got)
	}
	if !strings.Contains(r.Report.Text, "incompleta") {
		t.Errorf("sin aviso: %s", r.Report.Text)
	}
	if _, err := os.Stat(lote); err != nil {
		t.Error("se borró la carpeta de Patrol")
	}
}

// Quien llega segundo (vigilante o `mctl backup run`) recibe el resultado final, no un error de carpeta borrada.
func TestCollectRepiteElResultadoFinalDeUnTrabajoPropio(t *testing.T) {
	s, sd, info, _ := nuevo(t, "completed")
	_, pj := trabajoPropio(t, s, sd, info, 3)
	carpeta(t, pj, "hostname SW1\n")
	ctx := context.Background()
	r1, err := s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil || !r1.Done || r1.Error != "" {
		t.Fatalf("1: %+v %v", r1, err)
	}
	r2, err := s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil || !r2.Done || r2.Error != "" || r2.Report.Text != r1.Report.Text {
		t.Fatalf("2: %+v %v", r2, err)
	}
}

// Una ronda incompleta no detiene el avance: no se relee en cada vuelta (Save recrearía lo que Prune borró),
// y la carpeta de Patrol queda como única copia de lo incompleto.
func TestRondaIncompletaNoFrenaElAvance(t *testing.T) {
	s, sd, info, _ := nuevo(t, "running")
	lote, pj := trabajoPropio(t, s, sd, info, 3)
	os.MkdirAll(filepath.Join(pj, dev), 0o755)
	r1 := filepath.Join(pj, dev, "r001_20261106-100000.txt")
	os.WriteFile(r1, []byte("===== 2026-11-06T10:00:01Z · show running-config · incompleto =====\nhostname SW1\n"), 0o600)
	ctx := context.Background()
	if _, err := s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"}); err != nil {
		t.Fatal(err)
	}
	if len(s.jobs["j1"].done) != 1 {
		t.Fatalf("la ronda incompleta se volvería a leer: done=%v", s.jobs["j1"].done)
	}
	info.State = "completed"
	os.WriteFile(filepath.Join(pj, dev, "r002_20261106-101000.txt"), []byte("===== 2026-11-06T10:10:01Z · show running-config =====\nhostname SW1\n"), 0o600)
	r, err := s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if err != nil || strings.Count(ids(t, s), "-running") != 1 || !strings.Contains(r.Report.Text, "1 respaldo(s) guardado(s)") {
		t.Fatalf("%v %s", err, r.GetReport().GetText())
	}
	if _, err := os.Stat(lote); err != nil {
		t.Error("se borró la carpeta de Patrol con una ronda incompleta")
	}
}

// Patrol escribe la sección de un comando de una sola vez, pero un lector puede ver la escritura a medias: con el
// trabajo en marcha no se lee un .txt tocado hace un instante.
func TestNoGuardaUnTxtDePatrolQueSeEstaEscribiendo(t *testing.T) {
	s, _, info, dir := nuevo(t, "running")
	s.quiet = time.Hour
	carpeta(t, dir, "hostname SW1\nntp clock-period 1\n")
	ctx := i18n.WithLocale(context.Background(), i18n.Es)
	r, _ := s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if strings.Contains(r.Report.Text, "guardado(s)") && !strings.Contains(r.Report.Text, "0 respaldo(s) guardado(s)") {
		t.Fatalf("guardó un archivo recién tocado: %s", r.Report.Text)
	}
	// Quieto desde hace rato, pero la fecha acaba de cambiar respecto a la vuelta anterior: todavía no.
	old := time.Now().Add(-2 * time.Hour)
	fs, _ := filepath.Glob(filepath.Join(dir, "SW1_192.0.2.1", "*.txt"))
	os.Chtimes(fs[0], old, old)
	r, _ = s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if strings.Contains(r.Report.Text, "1 respaldo(s) guardado(s)") {
		t.Fatalf("lo leyó sin ver el mismo tamaño y fecha dos vueltas seguidas: %s", r.Report.Text)
	}
	// Dos vueltas seguidas con el mismo tamaño y fecha, y quieto: ya se lee.
	r, _ = s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if !strings.Contains(r.Report.Text, "1 respaldo(s) guardado(s)") {
		t.Fatalf("no lo leyó al quedar quieto: %s", r.Report.Text)
	}
	// Terminado el trabajo todo se lee aunque sea reciente.
	carpeta(t, dir, "hostname SW1\nntp clock-period 1\n", "hostname SW1\nvlan 10\n")
	info.State = "completed"
	r, _ = s.CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: "j1"})
	if !r.Done || !strings.Contains(r.Report.Text, "guardado(s)") {
		t.Fatalf("final: %+v", r)
	}
}
