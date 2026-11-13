// Package forensic es el servicio de la Fase 17: forense de logs y fallas. Todo es de solo
// lectura; trabaja con texto pegado, archivos locales o la carpeta de un trabajo de Patrol.
package forensic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/crashinfo"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/logintel"
	"github.com/oom-netsec/MACUAHUITL/internal/msgkb"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// forensicSvc nunca habla con los equipos.
type forensicSvc struct {
	v1.UnimplementedForensicServiceServer
	d service.Deps
	// logCap sustituye a maxLogBytes (solo pruebas); 0 = el tope normal.
	logCap int64
	// repCap sustituye a maxReport (solo pruebas).
	repCap int64
}

func (s *forensicSvc) reportBytes() int64 {
	if s.repCap > 0 {
		return s.repCap
	}
	return maxReport
}

func (s *forensicSvc) logBytes() int64 {
	if s.logCap > 0 {
		return s.logCap
	}
	return maxLogBytes
}

// maxText acota el texto que viaja en una petición (la UI pega; la CLI manda rutas).
const maxText = 8 << 20

// readSource devuelve el texto de la petición o el contenido de un archivo regular local
// (ruta absoluta, sin directorios ni dispositivos), leyendo a lo más max+1 bytes para que el
// dominio pueda avisar que se truncó.
func readSource(ctx context.Context, text, path string, max int) (string, error) {
	switch {
	case text != "" && path != "":
		return "", service.Err(ctx, codes.InvalidArgument, "forensic.err.both", nil)
	case text != "":
		if len(text) > maxText {
			return "", service.Err(ctx, codes.InvalidArgument, "forensic.err.text_big", i18n.A("mib", maxText>>20))
		}
		return text, nil
	case path == "":
		return "", service.Err(ctx, codes.InvalidArgument, "forensic.err.neither", nil)
	case !filepath.IsAbs(path):
		return "", service.Err(ctx, codes.InvalidArgument, "forensic.err.relative", nil)
	}
	f, err := sys.OpenRegular(filepath.Clean(path))
	if errors.Is(err, sys.ErrNotRegular) {
		return "", status.Error(codes.InvalidArgument, err.Error())
	}
	if err != nil {
		return "", status.Error(codes.NotFound, err.Error())
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return "", status.Error(codes.Internal, err.Error())
	}
	return string(b), nil
}

// maxReport acota por separado el JSON y el texto de un informe de lista larga (patrones,
// interfaces): los dos más el resto del mensaje caben holgados en ipc.MaxMsg.
const maxReport = 4 << 20

// fitReport empaqueta el informe que arma build con las primeras n filas de total. Si el JSON o
// el texto pasan de maxReport, reduce n y lo avisa en el propio informe (warn llega vacío si no
// hubo recorte). Las filas ya vienen ordenadas por importancia: se pierde la cola.
func (s *forensicSvc) fitReport(total int, build func(n int, warn i18n.Text) (any, string)) *v1.ToolReport {
	n, warn := total, i18n.Text{}
	for {
		v, txt := build(n, warn)
		r := service.Report(v, txt)
		size := max(len(r.Json), len(r.Text))
		if int64(size) <= s.reportBytes() || n == 0 {
			return r
		}
		n = min(int(int64(n)*s.reportBytes()/int64(size)*9/10), n-1)
		warn = i18n.Tx("forensic.warn.fit", "n", n, "total", total, "kib", s.reportBytes()>>10)
	}
}

func kb() (*msgkb.KB, error) {
	k, err := msgkb.Default()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return k, nil
}

// reportOf arma el informe con las fichas y el texto en el idioma de la llamada.
func lookupOf(loc string, es []msgkb.Entry) ([]msgkb.Entry, string) {
	es = msgkb.EntriesIn(loc, es)
	return es, msgkb.TextIn(loc, es)
}

func (s *forensicSvc) MsgLookup(ctx context.Context, r *v1.MsgLookupRequest) (*v1.MsgLookupResponse, error) {
	s.d.MarkActive()
	k, err := kb()
	if err != nil {
		return nil, err
	}
	es, err := k.Query(r.Query)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	if es == nil {
		es = []msgkb.Entry{}
	}
	s.d.Audit("forensic.msg", r.Query, fmt.Sprintf("results=%d", len(es)))
	es, txt := lookupOf(i18n.Locale(ctx), es)
	return &v1.MsgLookupResponse{Report: service.Report(es, txt)}, nil
}

// crashReport es la respuesta de Crashinfo: lo leído más la ficha de cada mensaje que el
// archivo menciona.
type crashReport struct {
	crashinfo.Report
	Messages []msgkb.Entry `json:"messages"`
}

func (s *forensicSvc) Crashinfo(ctx context.Context, r *v1.CrashinfoRequest) (*v1.CrashinfoResponse, error) {
	s.d.MarkActive()
	text, err := readSource(ctx, r.Text, r.Path, crashinfo.MaxBytes)
	if err != nil {
		return nil, err
	}
	rep, err := crashinfo.Parse(text)
	if err != nil {
		code := codes.InvalidArgument
		if !errors.Is(err, crashinfo.ErrEmpty) {
			code = codes.Internal
		}
		return nil, service.ErrFrom(ctx, code, err)
	}
	loc := i18n.Locale(ctx)
	out := crashReport{Report: rep.Localize(loc), Messages: []msgkb.Entry{}}
	k, err := kb()
	if err != nil {
		return nil, err
	}
	for _, m := range rep.Mnemonics {
		if e, ok := k.Lookup(m); ok {
			out.Messages = append(out.Messages, e)
		}
	}
	out.Messages = msgkb.EntriesIn(loc, out.Messages)
	txt := out.Report.TextIn(loc)
	if len(out.Messages) > 0 {
		txt += "\n\n" + i18n.Msg(loc, "forensic.crash.known", nil) + "\n" + msgkb.TextIn(loc, out.Messages)
	}
	s.d.Audit("forensic.crashinfo", strings.TrimSpace(r.Path), fmt.Sprintf("bytes=%d type=%s", rep.Bytes, rep.Kind))
	return &v1.CrashinfoResponse{Report: service.Report(out, txt)}, nil
}

// Module registra el servicio Forensic.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterForensicServiceServer(s, &forensicSvc{d: d})
}

func (s *forensicSvc) LogPatterns(ctx context.Context, r *v1.LogPatternsRequest) (*v1.LogPatternsResponse, error) {
	s.d.MarkActive()
	l, err := s.loadLogs(ctx, r.Source)
	if err != nil {
		return nil, err
	}
	o := logintel.GroupOptions{BurstCount: int(min(r.BurstCount, 1000)), BurstWindow: time.Duration(min(r.BurstWindowSeconds, 86400)) * time.Second}
	rep := logintel.Group(l.entries, o)
	rep.Warnings, rep.WarnT = append(slices.Clone(l.warnings), rep.Warnings...), append(slices.Clone(l.warnT), rep.WarnT...)
	loc := i18n.Locale(ctx)
	s.d.Audit("forensic.patterns", l.source.in(i18n.En), fmt.Sprintf("messages=%d patterns=%d", len(l.entries), len(rep.Patterns)))
	return &v1.LogPatternsResponse{Report: s.fitReport(len(rep.Patterns), func(n int, warn i18n.Text) (any, string) {
		r := rep
		r.Patterns = rep.Patterns[:n]
		if !warn.Empty() {
			r.Warnings, r.WarnT = append(r.Warnings[:len(r.Warnings):len(r.Warnings)], warn.In(i18n.Es)), append(r.WarnT[:len(r.WarnT):len(r.WarnT)], warn)
		}
		r = r.Localize(loc)
		out := struct {
			logintel.Report
			Source string         `json:"source"`
			Stats  logintel.Stats `json:"stats"`
		}{r, l.source.in(loc), l.stats}
		return out, i18n.Msg(loc, "forensic.label.source", nil) + ": " + l.source.in(loc) + "\n" + r.TextIn(loc)
	})}, nil
}

func (s *forensicSvc) DebugFilter(ctx context.Context, r *v1.DebugFilterRequest) (*v1.DebugFilterResponse, error) {
	s.d.MarkActive()
	if len(r.Noise) > logintel.MaxNoise {
		return nil, service.Err(ctx, codes.InvalidArgument, "forensic.err.noise_max", i18n.A("max", logintel.MaxNoise))
	}
	text, err := readSource(ctx, r.Text, r.Path, maxLogBytes)
	if err != nil {
		return nil, err
	}
	var warns []string
	var warnsT []i18n.Text
	if len(text) > maxLogBytes {
		text = text[:maxLogBytes]
		i18n.Note(&warns, &warnsT, "forensic.warn.file_cap")
	}
	rep := logintel.FilterDebug(text, logintel.DebugOptions{Noise: r.Noise, FamilyMin: int(min(r.FamilyMin, 1<<20)), RareMax: int(min(r.RareMax, 1<<20)), Top: int(min(r.Top, 500))})
	rep.Warnings, rep.WarnT = append(warns, rep.Warnings...), append(warnsT, rep.WarnT...)
	loc := i18n.Locale(ctx)
	rep = rep.Localize(loc)
	s.d.Audit("forensic.debugs", strings.TrimSpace(r.Path), fmt.Sprintf("lines=%d hidden=%d patterns=%d anomalies=%d", rep.Lines, rep.Hidden, rep.GroupsTotal, len(rep.Anomalies)))
	return &v1.DebugFilterResponse{Report: service.Report(rep, rep.TextIn(loc))}, nil
}
