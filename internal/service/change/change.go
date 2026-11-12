package change

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/change"
	"github.com/oom-netsec/MACUAHUITL/internal/compliance"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/upgrade"
)

// ---- Ventana de cambio ----
//
// Un cambio es un JobSpec de Patrol que se corre dos veces (PRE y POST). La recolección,
// el Login Test, la bóveda y la auditoría son las de Patrol; aquí solo se arma y se compara.

type changeRec struct {
	id   string
	spec *v1.JobSpec
	jobs [3]string // índice = ChangePhase
}

type changeSvc struct {
	v1.UnimplementedChangeServiceServer
	d       service.Deps
	mu      sync.Mutex
	changes map[string]*changeRec // shortcut: en memoria; tras reiniciar el núcleo, el reporte se pide por carpetas
}

const defaultChangePlaybook = "ios-xe/pre-post"

func (s *changeSvc) CreateChange(_ context.Context, r *v1.CreateChangeRequest) (*v1.CreateChangeResponse, error) {
	s.d.MarkActive()
	if r.Spec == nil {
		return nil, status.Error(codes.InvalidArgument, "falta la definición del cambio")
	}
	spec := proto.Clone(r.Spec).(*v1.JobSpec)
	spec.Kind = "change"
	if spec.Name == "" {
		spec.Name = "cambio"
	}
	if len(spec.PlaybookIds) == 0 && spec.CustomCommands == "" {
		spec.PlaybookIds = []string{defaultChangePlaybook}
	}
	if spec.WindowHours == 0 {
		spec.WindowHours = 4
	}
	creada := "" // carpeta que creó el núcleo: se borra si la petición no valida
	if spec.OutputDir == "" {
		// Una subcarpeta propia por cambio (0700): outputs/cambios puede existir con otro modo y no se corrige.
		root := filepath.Join(s.d.Outputs(), "cambios")
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, status.Errorf(codes.Internal, "carpeta de salida: %v", err)
		}
		dir, err := os.MkdirTemp(root, "cambio-")
		if err != nil {
			return nil, status.Errorf(codes.Internal, "carpeta de salida: %v", err)
		}
		spec.OutputDir, creada = dir, dir
	}
	// PRE y POST deben ser comparables: una ronda, un archivo por ronda, sin borrar los sueltos.
	spec.Schedule, spec.Split, spec.Zip, spec.DeleteLooseFiles = nil, v1.SplitStrategy_SPLIT_STRATEGY_PER_ROUND, v1.ZipPolicy_ZIP_POLICY_AT_END, false
	// Validar ya, con las mismas reglas que CreateJob, para no fallar en plena ventana.
	probe := proto.Clone(spec).(*v1.JobSpec)
	probe.Name += "-pre"
	if err := s.d.ValidateJob(probe); err != nil {
		if creada != "" {
			os.Remove(creada) // vacía: os.Remove no toca una con contenido
		}
		return nil, err
	}
	rec := &changeRec{id: service.NewID(), spec: spec}
	s.mu.Lock()
	s.changes[rec.id] = rec
	s.mu.Unlock()
	s.d.Audit("change.create", rec.id, fmt.Sprintf("name=%s devices=%d playbooks=%v", spec.Name, len(spec.Targets), spec.PlaybookIds))
	return &v1.CreateChangeResponse{ChangeId: rec.id}, nil
}

func (s *changeSvc) get(id string) (*changeRec, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.changes[id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "cambio %s no existe", id)
	}
	return rec, nil
}

func (s *changeSvc) jobState(id string) string {
	if id == "" {
		return ""
	}
	j, err := s.d.Job(id)
	if err != nil {
		return ""
	}
	return j.State
}

var phaseName = map[v1.ChangePhase]string{v1.ChangePhase_CHANGE_PHASE_PRE: "pre", v1.ChangePhase_CHANGE_PHASE_POST: "post"}

func (s *changeSvc) CaptureChange(ctx context.Context, r *v1.CaptureChangeRequest) (*v1.CaptureChangeResponse, error) {
	s.d.MarkActive()
	rec, err := s.get(r.ChangeId)
	if err != nil {
		return nil, err
	}
	name, ok := phaseName[r.Phase]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "fase no indicada (pre o post)")
	}
	s.mu.Lock()
	cur, pre := rec.jobs[r.Phase], rec.jobs[v1.ChangePhase_CHANGE_PHASE_PRE]
	s.mu.Unlock()
	if st := s.jobState(cur); st == "arming" || st == "armed" {
		return nil, status.Errorf(codes.FailedPrecondition, "la captura %s ya está en curso (trabajo %s)", name, cur)
	}
	if r.Phase == v1.ChangePhase_CHANGE_PHASE_POST && s.jobState(pre) != "completed" {
		return nil, status.Error(codes.FailedPrecondition, "primero termina la captura PRE: sin línea base no hay comparación")
	}
	spec := proto.Clone(rec.spec).(*v1.JobSpec)
	spec.Name += "-" + name
	p := s.d.Patrol()
	cj, err := p.CreateJob(ctx, &v1.CreateJobRequest{Spec: spec})
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	rec.jobs[r.Phase] = cj.JobId
	s.mu.Unlock()
	s.d.Audit("change.capture", rec.id, fmt.Sprintf("phase=%s job=%s", name, cj.JobId))
	ar, err := p.ArmJob(ctx, &v1.ArmJobRequest{JobId: cj.JobId, AcceptedHostKeyFingerprints: r.AcceptedHostKeyFingerprints, ExcludedDeviceIds: r.ExcludedDeviceIds})
	if err != nil {
		// El trabajo queda creado: se revisa con LoginTest y se arma con ArmJob, como cualquier otro.
		return &v1.CaptureChangeResponse{JobId: cj.JobId, Detail: status.Convert(err).Message()}, nil
	}
	return &v1.CaptureChangeResponse{JobId: cj.JobId, Armed: true, WindowEndsAt: ar.WindowEndsAt}, nil
}

func (s *changeSvc) ListChanges(context.Context, *v1.ListChangesRequest) (*v1.ListChangesResponse, error) {
	s.mu.Lock()
	var recs []changeRec
	for _, rec := range s.changes {
		recs = append(recs, *rec)
	}
	s.mu.Unlock()
	sort.Slice(recs, func(i, j int) bool { return recs[i].id < recs[j].id })
	out := &v1.ListChangesResponse{}
	for _, rec := range recs {
		pre, post := rec.jobs[v1.ChangePhase_CHANGE_PHASE_PRE], rec.jobs[v1.ChangePhase_CHANGE_PHASE_POST]
		out.Changes = append(out.Changes, &v1.ChangeSummary{ChangeId: rec.id, Name: rec.spec.Name, PreJobId: pre, PreState: s.jobState(pre),
			PostJobId: post, PostState: s.jobState(post)})
	}
	return out, nil
}

// outputDir: carpeta de un trabajo terminado.
func (s *changeSvc) outputDir(jobID, phase string) (string, error) {
	if jobID == "" {
		return "", status.Errorf(codes.FailedPrecondition, "falta la captura %s", phase)
	}
	j, err := s.d.Job(jobID)
	if err != nil {
		return "", err
	}
	if j.State != "completed" || j.Dir == "" {
		return "", status.Errorf(codes.FailedPrecondition, "la captura %s está %s", phase, j.State)
	}
	return j.Dir, nil
}

func (s *changeSvc) GetChangeReport(_ context.Context, r *v1.GetChangeReportRequest) (*v1.GetChangeReportResponse, error) {
	preDir, postDir := r.PreDir, r.PostDir
	if r.ChangeId != "" {
		rec, err := s.get(r.ChangeId)
		if err != nil {
			return nil, err
		}
		s.mu.Lock()
		pre, post := rec.jobs[v1.ChangePhase_CHANGE_PHASE_PRE], rec.jobs[v1.ChangePhase_CHANGE_PHASE_POST]
		s.mu.Unlock()
		if preDir, err = s.outputDir(pre, "PRE"); err != nil {
			return nil, err
		}
		if postDir, err = s.outputDir(post, "POST"); err != nil {
			return nil, err
		}
	} else if !filepath.IsAbs(preDir) || !filepath.IsAbs(postDir) {
		return nil, status.Error(codes.InvalidArgument, "indica el cambio o las dos carpetas (rutas absolutas)")
	}
	a, err := capture.ReadDir(preDir)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	b, err := capture.ReadDir(postDir)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	rep := change.Compare(a, b)
	s.d.Audit("change.report", r.ChangeId, fmt.Sprintf("pre=%s post=%s devices=%d", preDir, postDir, len(rep.Devices)))
	return &v1.GetChangeReportResponse{Report: service.Report(rep, rep.Text())}, nil
}

func (s *changeSvc) CheckUpgrade(_ context.Context, r *v1.CheckUpgradeRequest) (*v1.CheckUpgradeResponse, error) {
	s.d.MarkActive()
	outs := capture.Split(r.Outputs)
	if len(outs) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no se reconocieron salidas: usa un archivo de Patrol o una sesión con prompts (SW1#show version)")
	}
	rep, err := upgrade.Check(outs, upgrade.Image{File: r.ImageFile, Size: r.ImageSize, MD5: r.ImageMd5}, r.VerifyOutput)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.d.Audit("upgrade.check", rep.Hostname, fmt.Sprintf("image=%s commands=%d", r.ImageFile, len(outs)))
	return &v1.CheckUpgradeResponse{Report: service.Report(rep, rep.Text())}, nil
}

func (s *changeSvc) CheckCompliance(_ context.Context, r *v1.CheckComplianceRequest) (*v1.CheckComplianceResponse, error) {
	s.d.MarkActive()
	rep, err := compliance.Check(r.Config, r.Template)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.d.Audit("compliance.check", "", fmt.Sprintf("ok=%d failures=%d warnings=%d template=%t", rep.Pass, rep.Fail, rep.Warn, r.Template != ""))
	return &v1.CheckComplianceResponse{Report: service.Report(rep, rep.Text())}, nil
}

// Module registra el servicio Change.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterChangeServiceServer(s, &changeSvc{d: d, changes: map[string]*changeRec{}})
}
