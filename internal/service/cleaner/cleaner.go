package cleaner

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/cleaner"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// cleanerSvc trabaja solo con el texto de la petición: sin archivos ni red.
type cleanerSvc struct {
	v1.UnimplementedCleanerServiceServer
	d service.Deps
}

func (s *cleanerSvc) Clean(ctx context.Context, r *v1.CleanRequest) (*v1.CleanResponse, error) {
	s.d.MarkActive()
	if r.Text == "" {
		return nil, service.Err(ctx, codes.InvalidArgument, "cleaner.err.empty", nil)
	}
	res := cleaner.Clean(r.Text, cleaner.Options{Sort: r.Sort})
	s.d.Audit("cleaner.clean", "", fmt.Sprintf("bytes=%d sorted=%v changes=%d orphans=%d", len(r.Text), r.Sort, len(res.Changes), len(res.Orphans)))
	out := res.OutputIn(i18n.Locale(ctx))
	res.Output = "" // la salida viaja aparte; el informe no la repite
	return &v1.CleanResponse{Report: service.ReportL(ctx, &res, func(loc string) string { return res.TextIn(loc) }), Output: out}, nil
}

// Module registra el servicio Cleaner.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterCleanerServiceServer(s, &cleanerSvc{d: d})
}
