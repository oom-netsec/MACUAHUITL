package forensic

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/logintel"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// isProcMem: show processes memory [sorted [holding]], no la variante "platform" (otras columnas).
func isProcMem(cmd string) bool {
	c := strings.ToLower(strings.Join(strings.Fields(cmd), " "))
	return (strings.HasPrefix(c, "show processes memory") || strings.HasPrefix(c, "show process memory")) && !strings.Contains(c, "platform")
}

func (s *forensicSvc) MemLeaks(ctx context.Context, r *v1.MemLeaksRequest) (*v1.MemLeaksResponse, error) {
	s.d.MarkActive()
	if r.Job == "" {
		return nil, service.Err(ctx, codes.InvalidArgument, "forensic.err.no_job", nil)
	}
	b, err := s.bundle(ctx, r.Job)
	if err != nil {
		return nil, err
	}
	var ss []logintel.MemSample
	var warns []string
	var warnsT []i18n.Text
	seen := map[string]bool{}
	for _, sec := range b.Sections {
		if sec.Invalid || sec.Incomplete || !isProcMem(sec.Command) {
			continue
		}
		if d := strings.ToLower(r.Device); d != "" && !strings.Contains(strings.ToLower(sec.Device), d) {
			continue
		}
		k := fmt.Sprintf("%s\x00%d", sec.Device, sec.Round) // un comando por equipo y ronda
		if seen[k] {
			continue
		}
		seen[k] = true
		ps, ok := iosxe.ParseProcessMemory(sec.Text)
		if !ok {
			i18n.Note(&warns, &warnsT, "forensic.warn.mem_format", "device", sec.Device, "round", sec.Round)
			continue
		}
		m := logintel.MemSample{Host: sec.Device, Round: sec.Round, At: sec.At}
		for _, p := range ps {
			m.Procs = append(m.Procs, logintel.Proc{PID: p.PID, Name: p.Name, Holding: p.Holding})
		}
		ss = append(ss, m)
	}
	rep := logintel.MemLeaks(ss, logintel.LeakOptions{MinRounds: int(min(r.MinRounds, 1000)), MinGrowth: int64(min(r.MinGrowthKib, 1<<30)) << 10})
	rep.Warnings, rep.WarnT = append(warns, rep.Warnings...), append(warnsT, rep.WarnT...)
	loc := i18n.Locale(ctx)
	rep = rep.Localize(loc)
	out := struct {
		logintel.LeakReport
		Job string `json:"job"`
	}{rep, b.Dir}
	s.d.Audit("forensic.memleaks", b.Dir, fmt.Sprintf("device=%q samples=%d suspects=%d", r.Device, len(ss), len(rep.Leaks)))
	return &v1.MemLeaksResponse{Report: service.Report(out, rep.TextIn(loc))}, nil
}
