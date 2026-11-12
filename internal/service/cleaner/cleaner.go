package cleaner

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/cleaner"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// cleanerSvc trabaja solo con el texto de la petición: sin archivos ni red.
type cleanerSvc struct {
	v1.UnimplementedCleanerServiceServer
	d service.Deps
}

func (s *cleanerSvc) Clean(_ context.Context, r *v1.CleanRequest) (*v1.CleanResponse, error) {
	s.d.MarkActive()
	if r.Text == "" {
		return nil, status.Error(codes.InvalidArgument, "falta la configuración")
	}
	res := cleaner.Clean(r.Text, cleaner.Options{Sort: r.Sort})
	s.d.Audit("cleaner.clean", "", fmt.Sprintf("bytes=%d orden=%v cambios=%d huerfanas=%d", len(r.Text), r.Sort, len(res.Changes), len(res.Orphans)))
	out := res.Output
	res.Output = "" // la salida viaja aparte; el informe no la repite
	return &v1.CleanResponse{Report: service.Report(res, res.Text()), Output: out}, nil
}

// Module registra el servicio Cleaner.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterCleanerServiceServer(s, &cleanerSvc{d: d})
}
