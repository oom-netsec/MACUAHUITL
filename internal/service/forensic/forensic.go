// Package forensic es el servicio de la Fase 17: forense de logs y fallas. Todo es de solo
// lectura; trabaja con texto pegado, archivos locales o la carpeta de un trabajo de Patrol.
package forensic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/crashinfo"
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
func readSource(text, path string, max int) (string, error) {
	switch {
	case text != "" && path != "":
		return "", status.Error(codes.InvalidArgument, "manda el texto o la ruta, no los dos")
	case text != "":
		if len(text) > maxText {
			return "", status.Errorf(codes.InvalidArgument, "el texto excede %d MiB", maxText>>20)
		}
		return text, nil
	case path == "":
		return "", status.Error(codes.InvalidArgument, "falta el texto o la ruta del archivo")
	case !filepath.IsAbs(path):
		return "", status.Error(codes.InvalidArgument, "la ruta del archivo debe ser absoluta")
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
func (s *forensicSvc) fitReport(total int, build func(n int, warn string) (any, string)) *v1.ToolReport {
	n, warn := total, ""
	for {
		v, txt := build(n, warn)
		r := service.Report(v, txt)
		size := max(len(r.Json), len(r.Text))
		if int64(size) <= s.reportBytes() || n == 0 {
			return r
		}
		n = min(int(int64(n)*s.reportBytes()/int64(size)*9/10), n-1)
		warn = fmt.Sprintf("informe recortado: se muestran %d de %d filas por el tope de %d KiB; acota la fuente (equipo, archivo o rango)", n, total, s.reportBytes()>>10)
	}
}

func kb() (*msgkb.KB, error) {
	k, err := msgkb.Default()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return k, nil
}

func (s *forensicSvc) MsgLookup(_ context.Context, r *v1.MsgLookupRequest) (*v1.MsgLookupResponse, error) {
	s.d.MarkActive()
	k, err := kb()
	if err != nil {
		return nil, err
	}
	es, err := k.Query(r.Query)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if es == nil {
		es = []msgkb.Entry{}
	}
	s.d.Audit("forensic.msg", r.Query, fmt.Sprintf("resultados=%d", len(es)))
	return &v1.MsgLookupResponse{Report: service.Report(es, msgkb.Text(es))}, nil
}

// crashReport es la respuesta de Crashinfo: lo leído más la ficha de cada mensaje que el
// archivo menciona.
type crashReport struct {
	crashinfo.Report
	Messages []msgkb.Entry `json:"messages"`
}

func (s *forensicSvc) Crashinfo(_ context.Context, r *v1.CrashinfoRequest) (*v1.CrashinfoResponse, error) {
	s.d.MarkActive()
	text, err := readSource(r.Text, r.Path, crashinfo.MaxBytes)
	if err != nil {
		return nil, err
	}
	rep, err := crashinfo.Parse(text)
	if err != nil {
		code := codes.InvalidArgument
		if !errors.Is(err, crashinfo.ErrEmpty) {
			code = codes.Internal
		}
		return nil, status.Error(code, err.Error())
	}
	out := crashReport{Report: rep, Messages: []msgkb.Entry{}}
	k, err := kb()
	if err != nil {
		return nil, err
	}
	for _, m := range rep.Mnemonics {
		if e, ok := k.Lookup(m); ok {
			out.Messages = append(out.Messages, e)
		}
	}
	txt := rep.Text()
	if len(out.Messages) > 0 {
		txt += "\n\nMensajes conocidos:\n" + msgkb.Text(out.Messages)
	}
	s.d.Audit("forensic.crashinfo", strings.TrimSpace(r.Path), fmt.Sprintf("bytes=%d tipo=%s", rep.Bytes, rep.Kind))
	return &v1.CrashinfoResponse{Report: service.Report(out, txt)}, nil
}

// Module registra el servicio Forensic.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterForensicServiceServer(s, &forensicSvc{d: d})
}

func (s *forensicSvc) LogPatterns(_ context.Context, r *v1.LogPatternsRequest) (*v1.LogPatternsResponse, error) {
	s.d.MarkActive()
	l, err := s.loadLogs(r.Source)
	if err != nil {
		return nil, err
	}
	o := logintel.GroupOptions{BurstCount: int(min(r.BurstCount, 1000)), BurstWindow: time.Duration(min(r.BurstWindowSeconds, 86400)) * time.Second}
	rep := logintel.Group(l.entries, o)
	rep.Warnings = append(l.warnings, rep.Warnings...)
	s.d.Audit("forensic.patterns", l.source, fmt.Sprintf("mensajes=%d patrones=%d", len(l.entries), len(rep.Patterns)))
	return &v1.LogPatternsResponse{Report: s.fitReport(len(rep.Patterns), func(n int, warn string) (any, string) {
		r := rep
		r.Patterns = rep.Patterns[:n]
		if warn != "" {
			r.Warnings = append(r.Warnings[:len(r.Warnings):len(r.Warnings)], warn)
		}
		out := struct {
			logintel.Report
			Source string         `json:"source"`
			Stats  logintel.Stats `json:"stats"`
		}{r, l.source, l.stats}
		return out, "Fuente: " + l.source + "\n" + r.Text()
	})}, nil
}

func (s *forensicSvc) DebugFilter(_ context.Context, r *v1.DebugFilterRequest) (*v1.DebugFilterResponse, error) {
	s.d.MarkActive()
	if len(r.Noise) > logintel.MaxNoise {
		return nil, status.Errorf(codes.InvalidArgument, "como máximo %d textos de ruido", logintel.MaxNoise)
	}
	text, err := readSource(r.Text, r.Path, maxLogBytes)
	if err != nil {
		return nil, err
	}
	var warns []string
	if len(text) > maxLogBytes {
		text = text[:maxLogBytes]
		warns = append(warns, "el archivo supera 32 MiB: solo se leyó el principio")
	}
	rep := logintel.FilterDebug(text, logintel.DebugOptions{Noise: r.Noise, FamilyMin: int(min(r.FamilyMin, 1<<20)), RareMax: int(min(r.RareMax, 1<<20)), Top: int(min(r.Top, 500))})
	rep.Warnings = append(warns, rep.Warnings...)
	s.d.Audit("forensic.debugs", strings.TrimSpace(r.Path), fmt.Sprintf("lineas=%d ocultas=%d patrones=%d anomalias=%d", rep.Lines, rep.Hidden, rep.GroupsTotal, len(rep.Anomalies)))
	return &v1.DebugFilterResponse{Report: service.Report(rep, rep.Text())}, nil
}
