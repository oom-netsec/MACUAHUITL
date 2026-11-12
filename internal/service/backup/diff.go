package backup

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/backup"
	"github.com/oom-netsec/MACUAHUITL/internal/drift"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// diffReport compara dos respaldos del mismo equipo y tipo con la lógica de internal/drift
// (misma lista de líneas volátiles).
type diffReport struct {
	From    backup.Entry   `json:"from"`
	To      backup.Entry   `json:"to"`
	Added   int            `json:"added"`
	Removed int            `json:"removed"`
	Changes []drift.Change `json:"changes"`
	Ignored []string       `json:"ignored"`
	// Masked: alguno de los dos se tomó enmascarado, así que un cambio de secretos no se ve.
	Masked bool `json:"masked"`
}

func (r diffReport) text() string {
	var b strings.Builder
	if r.Masked {
		fmt.Fprintf(&b, "AVISO: %s\n\n", drift.MaskedNotice)
	}
	fmt.Fprintf(&b, "%s: %s contra %s\n", r.To.Device, r.To.ID[strings.Index(r.To.ID, "/")+1:], r.From.ID[strings.Index(r.From.ID, "/")+1:])
	if len(r.Changes) == 0 {
		b.WriteString("sin diferencias\n")
	} else {
		fmt.Fprintf(&b, "%d cambios (%d agregadas, %d quitadas)\n", len(r.Changes), r.Added, r.Removed)
	}
	last := "\x00"
	for _, c := range r.Changes {
		if c.Path != last {
			if c.Path != "" {
				fmt.Fprintf(&b, "  %s\n", c.Path)
			}
			last = c.Path
		}
		fmt.Fprintf(&b, "    %s %s\n", c.Op, strings.ReplaceAll(c.Line, "\n", "\n      "))
	}
	if len(r.Ignored) > 0 {
		fmt.Fprintf(&b, "  ignoradas por volátiles: %s\n", strings.Join(r.Ignored, "; "))
	}
	return b.String()
}

func (s *backupSvc) DiffBackups(_ context.Context, r *v1.DiffBackupsRequest) (*v1.DiffBackupsResponse, error) {
	s.d.MarkActive()
	st := s.store()
	from, a, err := st.Get(r.From)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	to, b, err := st.Get(r.To)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if from.Device != to.Device || from.Kind != to.Kind {
		return nil, status.Error(codes.InvalidArgument, "compara dos respaldos del mismo equipo y del mismo tipo")
	}
	cs, ign := drift.Compare(a, b)
	d := drift.NewDevice(to.Device, 0, 0, cs, ign)
	rep := diffReport{From: from, To: to, Added: d.Added, Removed: d.Removed, Changes: d.Changes, Ignored: d.Ignored, Masked: from.Masked || to.Masked}
	s.d.Audit("backup.diff", to.Device, fmt.Sprintf("from=%s to=%s changes=%d", from.ID, to.ID, len(cs)))
	return &v1.DiffBackupsResponse{Report: service.Report(rep, rep.text())}, nil
}
