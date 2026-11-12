package analysis

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/pcapan"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// analysisSvc solo lee archivos locales: el paquete de Patrol, outputs/syslog,
// la auditoría y un pcap opcional. Nunca habla con los equipos.
type analysisSvc struct {
	v1.UnimplementedAnalysisServiceServer
	d service.Deps
}

// timelineMargin: sin ventana, el syslog y la auditoría entran si caen hasta 15 min
// antes o después de las rondas del trabajo.
const timelineMargin = 15 * time.Minute

// maxSyslogBytes acota lo que una consulta de línea de tiempo lee de outputs/syslog.
const maxSyslogBytes = 64 << 20

// bundle acepta el ID de un trabajo de esta sesión o la ruta absoluta de su carpeta.
// upTo > 0 carga solo hasta esa ronda.
func (s *analysisSvc) bundle(job string, upTo int) (*analyze.Bundle, error) {
	dir := filepath.Clean(job)
	if !filepath.IsAbs(job) {
		j, err := s.d.Job(job)
		if err != nil {
			return nil, err
		}
		if j.Dir == "" {
			return nil, status.Error(codes.FailedPrecondition, "el trabajo aún no tiene salidas: ármalo y espera la primera ronda")
		}
		dir = j.Dir
	}
	b, err := analyze.LoadUpTo(dir, upTo)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return b, nil
}

func rulesOrErr() ([]analyze.Rule, error) {
	rs, err := analyze.DefaultRules()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return rs, nil
}

func (s *analysisSvc) AnalyzeJob(_ context.Context, r *v1.AnalyzeJobRequest) (*v1.AnalyzeJobResponse, error) {
	s.d.MarkActive()
	b, err := s.bundle(r.Job, int(r.Round))
	if err != nil {
		return nil, err
	}
	rs, err := rulesOrErr()
	if err != nil {
		return nil, err
	}
	rep := analyze.Analyze(b, rs, analyze.Options{Round: int(r.Round), Device: r.Device})
	s.d.Audit("analysis.run", b.Dir, fmt.Sprintf("ronda=%d equipo=%q hallazgos=%d", r.Round, r.Device, len(rep.Findings)))
	return &v1.AnalyzeJobResponse{Report: service.Report(rep, rep.Text())}, nil
}

func (s *analysisSvc) DiffRounds(_ context.Context, r *v1.DiffRoundsRequest) (*v1.DiffRoundsResponse, error) {
	s.d.MarkActive()
	b, err := s.bundle(r.Job, int(max(r.From, r.To)))
	if err != nil {
		return nil, err
	}
	rep, err := analyze.Diff(b, int(r.From), int(r.To), r.Device)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.d.Audit("analysis.diff", b.Dir, fmt.Sprintf("de=%d a=%d equipo=%q", r.From, r.To, r.Device))
	return &v1.DiffRoundsResponse{Report: service.Report(rep, rep.Text())}, nil
}

func (s *analysisSvc) Timeline(ctx context.Context, r *v1.TimelineRequest) (*v1.TimelineResponse, error) {
	s.d.MarkActive()
	if r.PcapPath != "" && !filepath.IsAbs(r.PcapPath) {
		return nil, status.Error(codes.InvalidArgument, "la ruta de la captura debe ser absoluta")
	}
	b, err := s.bundle(r.Job, 0)
	if err != nil {
		return nil, err
	}
	rs, err := rulesOrErr()
	if err != nil {
		return nil, err
	}
	o := analyze.TimelineOptions{Device: r.Device}
	from, to := b.Span()
	from, to = from.Add(-timelineMargin), to.Add(timelineMargin)
	if r.Around != nil {
		o.Around, o.Window = r.Around.AsTime(), 30*time.Second
		if r.WindowSeconds > 0 {
			o.Window = time.Duration(r.WindowSeconds) * time.Second
		}
		from, to = o.Around.Add(-o.Window), o.Around.Add(o.Window)
	}
	rep := analyze.TimelineReport{Dir: b.Dir, Around: o.Around}
	if !o.Around.IsZero() {
		rep.Window = o.Window.String()
	}
	evs, warns := analyze.BundleEvents(b, analyze.Analyze(b, rs, analyze.Options{}).Findings)
	rep.Warnings = append(append([]analyze.Warning{}, b.Warnings...), warns...)
	files, _ := filepath.Glob(filepath.Join(s.d.Outputs(), "syslog", "*.log"))
	extra, w := analyze.SyslogFiles(files, from, to, maxSyslogBytes)
	rep.Warnings = append(rep.Warnings, w...)
	b.Resolve(extra)
	var buf bytes.Buffer
	if err := s.d.ExportAudit(ctx, &buf, from, to); err != nil {
		rep.Warnings = append(rep.Warnings, analyze.Warning{Msg: "auditoría: " + err.Error()})
	}
	extra = append(extra, analyze.AuditEvents(&buf)...)
	if r.PcapPath != "" {
		pr, err := pcapan.Analyze(ctx, r.PcapPath, pcapan.Options{})
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		extra = append(extra, analyze.PcapEvents(pr)...)
		for _, w := range pr.Warnings {
			rep.Warnings = append(rep.Warnings, analyze.Warning{Msg: "pcap: " + w})
		}
	}
	for _, e := range extra {
		if !e.At.Before(from) && !e.At.After(to) {
			evs = append(evs, e)
		}
	}
	rep.Events = analyze.Timeline(evs, o)
	s.d.Audit("analysis.timeline", b.Dir, fmt.Sprintf("equipo=%q alrededor=%s ventana=%s pcap=%s eventos=%d", r.Device, fmtTime(o.Around), rep.Window, r.PcapPath, len(rep.Events)))
	return &v1.TimelineResponse{Report: service.Report(rep, rep.Text())}, nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

// Module registra el servicio Analysis.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterAnalysisServiceServer(s, &analysisSvc{d: d})
}
