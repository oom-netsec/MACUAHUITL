package adhoc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/adhoc"
	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// adhocSvc corre el lote como un trabajo de Patrol de una ronda: bóveda, Login Test, guard
// y auditoría son los de Patrol. Los comandos pasan por CheckDenied antes de crear nada.
type adhocSvc struct {
	v1.UnimplementedAdhocServiceServer
	d    service.Deps
	mu   sync.Mutex
	cmds map[string][]string // shortcut: en memoria; tras reiniciar el núcleo las columnas salen ordenadas por nombre
}

func (s *adhocSvc) StartAdhoc(ctx context.Context, r *v1.StartAdhocRequest) (*v1.StartAdhocResponse, error) {
	s.d.MarkActive()
	cmds, err := adhoc.Commands(r.Commands)
	if err != nil {
		s.d.Audit("adhoc.denied", "", err.Error())
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if len(r.Targets) == 0 {
		return nil, status.Error(codes.InvalidArgument, "indica al menos un equipo")
	}
	root := filepath.Join(s.d.Outputs(), "adhoc")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, status.Errorf(codes.Internal, "carpeta de salida: %v", err)
	}
	// Una carpeta por lote: el sello de tiempo de Patrol es de un segundo y dos lotes seguidos compartirían manifest, salidas y zip.
	dir, err := os.MkdirTemp(root, "lote-")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "carpeta de salida: %v", err)
	}
	// Una ronda, un archivo por ronda y sin borrar sueltos: capture.ReadDir lee así.
	spec := &v1.JobSpec{Name: "adhoc", Targets: r.Targets, DefaultCredentialId: r.CredentialId, CustomCommands: strings.Join(cmds, "\n"),
		OutputDir: dir, Kind: "adhoc", WindowHours: 1, Split: v1.SplitStrategy_SPLIT_STRATEGY_PER_ROUND, Zip: v1.ZipPolicy_ZIP_POLICY_AT_END}
	p := s.d.Patrol()
	cj, err := p.CreateJob(ctx, &v1.CreateJobRequest{Spec: spec})
	if err != nil {
		os.Remove(dir) // vacía: el trabajo no se creó
		return nil, err
	}
	s.mu.Lock()
	s.cmds[cj.JobId] = cmds
	s.mu.Unlock()
	s.d.Audit("adhoc.start", cj.JobId, fmt.Sprintf("equipos=%d comandos=%q", len(r.Targets), cmds))
	ar, err := p.ArmJob(ctx, &v1.ArmJobRequest{JobId: cj.JobId, AcceptedHostKeyFingerprints: r.AcceptedHostKeyFingerprints, ExcludedDeviceIds: r.ExcludedDeviceIds})
	if err != nil {
		// El trabajo queda creado: se revisa con LoginTest y se arma con ArmJob, como cualquier otro.
		return &v1.StartAdhocResponse{JobId: cj.JobId, Detail: status.Convert(err).Message()}, nil
	}
	return &v1.StartAdhocResponse{JobId: cj.JobId, Armed: true, WindowEndsAt: ar.WindowEndsAt}, nil
}

func (s *adhocSvc) AdhocResult(_ context.Context, r *v1.AdhocResultRequest) (*v1.AdhocResultResponse, error) {
	s.d.MarkActive()
	j, err := s.d.Job(r.JobId)
	if err != nil {
		return nil, err
	}
	out := &v1.AdhocResultResponse{State: j.State}
	switch j.State {
	case "cancelled":
		s.forget(r.JobId)
		out.Done = true
		return out, nil
	case "failed": // el núcleo cayó con el lote armado; no se reanuda
		out.Done, out.Error = true, "el núcleo se detuvo con el lote en curso; vuelve a lanzarlo"
		s.forget(r.JobId)
		return out, nil
	case "completed":
		if j.Dir == "" { // nunca se lee una carpeta vacía: sería el directorio de trabajo del demonio
			s.forget(r.JobId)
			out.Done, out.Error = true, "el lote no conserva su carpeta de salida"
			return out, nil
		}
	default:
		return out, nil
	}
	devs, err := capture.ReadDir(j.Dir)
	if err != nil {
		if j.FinishErr != "" { // el cierre falló: no habrá manifest, que el cliente no espere para siempre
			s.d.Audit("adhoc.failed", r.JobId, j.FinishErr)
			s.forget(r.JobId)
			out.Done, out.Error = true, j.FinishErr
			return out, nil
		}
		return out, nil // el manifest se escribe justo después de "completed": el cliente vuelve a preguntar
	}
	s.mu.Lock()
	cmds := s.cmds[r.JobId]
	delete(s.cmds, r.JobId) // shortcut: tras entregar, un segundo AdhocResult saca las columnas ordenadas por nombre
	s.mu.Unlock()
	if cmds == nil {
		seen := map[string]bool{}
		for _, d := range devs {
			for k := range d.Outputs {
				if !seen[k] {
					seen[k] = true
					cmds = append(cmds, k)
				}
			}
		}
		sort.Strings(cmds)
	}
	rep := adhoc.Build(devs, cmds)
	s.d.Audit("adhoc.result", r.JobId, fmt.Sprintf("equipos=%d filas=%d", len(devs), len(rep.Rows)))
	out.Done, out.Report, out.Csv, out.Markdown = true, service.Report(rep, rep.Text()), rep.CSV(), rep.Markdown()
	return out, nil
}

func (s *adhocSvc) forget(job string) {
	s.mu.Lock()
	delete(s.cmds, job)
	s.mu.Unlock()
}

// Module registra el servicio Adhoc.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterAdhocServiceServer(s, &adhocSvc{d: d, cmds: map[string][]string{}})
}
