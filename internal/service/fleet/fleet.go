package fleet

import (
	"context"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/fleet"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// fleetSvc solo lee los archivos de outputs/: nunca habla con los equipos.
type fleetSvc struct {
	v1.UnimplementedFleetServiceServer
	d service.Deps
}

func (s *fleetSvc) load(action, dir, detail string) (*fleet.Fleet, error) {
	s.d.MarkActive()
	var extra []string
	if dir == "" { // sin carpeta explícita: outputs/ y los output_dir de los trabajos
		dir = s.d.Outputs()
		extra = service.JobOutputRoots(s.d)
	}
	if !filepath.IsAbs(dir) {
		return nil, status.Errorf(codes.InvalidArgument, "la ruta %q debe ser absoluta", dir)
	}
	f, err := fleet.Load(dir, time.Now().UTC(), extra...)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	s.d.Audit("fleet."+action, dir, detail)
	return f, nil
}

func (s *fleetSvc) Find(_ context.Context, r *v1.FindRequest) (*v1.FindResponse, error) {
	if r.Query == "" {
		return nil, status.Error(codes.InvalidArgument, "indica una IP, MAC o nombre")
	}
	f, err := s.load("find", r.Dir, r.Query)
	if err != nil {
		return nil, err
	}
	res := f.Find(r.Query)
	return &v1.FindResponse{Report: service.Report(res, f.FindText(res))}, nil
}

func (s *fleetSvc) Trace(_ context.Context, r *v1.TraceRequest) (*v1.TraceResponse, error) {
	if r.Query == "" {
		return nil, status.Error(codes.InvalidArgument, "indica una MAC o una IP")
	}
	f, err := s.load("trace", r.Dir, r.Query)
	if err != nil {
		return nil, err
	}
	res := f.Trace(r.Query)
	return &v1.TraceResponse{Report: service.Report(res, f.TraceText(res))}, nil
}

func (s *fleetSvc) Path(_ context.Context, r *v1.PathRequest) (*v1.PathResponse, error) {
	if r.Query == "" || r.Dst == "" {
		return nil, status.Error(codes.InvalidArgument, "indica origen y destino")
	}
	f, err := s.load("path", r.Dir, r.Query+" -> "+r.Dst)
	if err != nil {
		return nil, err
	}
	res := f.Path(r.Query, r.Dst)
	return &v1.PathResponse{Report: service.Report(res, f.PathText(res)), Svg: res.SVG()}, nil
}

func (s *fleetSvc) Health(_ context.Context, r *v1.HealthRequest) (*v1.HealthResponse, error) {
	f, err := s.load("health", r.Dir, "")
	if err != nil {
		return nil, err
	}
	res := f.Health()
	return &v1.HealthResponse{Report: service.Report(res, f.HealthText(res))}, nil
}

func (s *fleetSvc) Summary(_ context.Context, r *v1.SummaryRequest) (*v1.SummaryResponse, error) {
	f, err := s.load("summary", r.Dir, "")
	if err != nil {
		return nil, err
	}
	res := f.Summary()
	return &v1.SummaryResponse{Report: service.Report(res, f.SummaryText(res))}, nil
}

func (s *fleetSvc) Capacity(_ context.Context, r *v1.CapacityRequest) (*v1.CapacityResponse, error) {
	var need int64
	if r.Need != "" {
		n, err := fleet.ParseSize(r.Need)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		need = n
	}
	f, err := s.load("capacity", r.Dir, r.Need)
	if err != nil {
		return nil, err
	}
	res := f.Capacity(need)
	return &v1.CapacityResponse{Report: service.Report(res, f.CapacityText(res))}, nil
}

func (s *fleetSvc) Inventory(_ context.Context, r *v1.InventoryRequest) (*v1.InventoryResponse, error) {
	f, err := s.load("inventory", r.Dir, "")
	if err != nil {
		return nil, err
	}
	res := f.Inventory()
	return &v1.InventoryResponse{Report: service.Report(res, f.InventoryText(res)), Csv: res.CSV(), Markdown: res.Markdown()}, nil
}

// Module registra el servicio Fleet.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterFleetServiceServer(s, &fleetSvc{d: d})
}
