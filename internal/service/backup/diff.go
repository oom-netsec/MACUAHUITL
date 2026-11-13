package backup

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/backup"
	"github.com/oom-netsec/MACUAHUITL/internal/drift"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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

func (r diffReport) text(loc string) string {
	var b strings.Builder
	if r.Masked {
		b.WriteString(i18n.Msg(loc, "backup.rep.notice", i18n.A("w", i18n.Msg(loc, "drift.masked_notice", nil))) + "\n\n")
	}
	b.WriteString(i18n.Msg(loc, "backup.diff.head", i18n.A("device", r.To.Device, "to", r.To.ID[strings.Index(r.To.ID, "/")+1:], "from", r.From.ID[strings.Index(r.From.ID, "/")+1:])) + "\n")
	if len(r.Changes) == 0 {
		b.WriteString(i18n.Msg(loc, "backup.diff.none", nil) + "\n")
	} else {
		b.WriteString(i18n.Msg(loc, "backup.diff.count", i18n.A("n", len(r.Changes), "added", r.Added, "removed", r.Removed)) + "\n")
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
		b.WriteString(i18n.Msg(loc, "backup.diff.ignored", i18n.A("list", strings.Join(r.Ignored, "; "))) + "\n")
	}
	return b.String()
}

func (s *backupSvc) DiffBackups(ctx context.Context, r *v1.DiffBackupsRequest) (*v1.DiffBackupsResponse, error) {
	s.d.MarkActive()
	st := s.store()
	from, a, err := st.Get(r.From)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.NotFound, err)
	}
	to, b, err := st.Get(r.To)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.NotFound, err)
	}
	if from.Device != to.Device || from.Kind != to.Kind {
		return nil, service.Err(ctx, codes.InvalidArgument, "backup.err.diff_mismatch", nil)
	}
	cs, ign := drift.Compare(a, b)
	d := drift.NewDevice(to.Device, 0, 0, cs, ign)
	rep := diffReport{From: from, To: to, Added: d.Added, Removed: d.Removed, Changes: d.Changes, Ignored: d.Ignored, Masked: from.Masked || to.Masked}
	s.d.Audit("backup.diff", to.Device, fmt.Sprintf("from=%s to=%s changes=%d", from.ID, to.ID, len(cs)))
	return &v1.DiffBackupsResponse{Report: service.Report(rep, rep.text(i18n.Locale(ctx)))}, nil
}
