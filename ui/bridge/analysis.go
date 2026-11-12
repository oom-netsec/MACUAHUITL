package bridge

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Análisis (hallazgos, diff entre rondas, línea de tiempo) ----
// Devuelven el JSON del reporte: la UI pinta hallazgos, diferencias y eventos con estructura.

func (b *Bridge) AnalysisRun(job string, round int, device string) (string, error) {
	if round < 0 {
		return "", wrapErr(fmt.Errorf("ronda %d inválida", round))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAnalysisServiceClient(c).AnalyzeJob(ctx, &v1.AnalyzeJobRequest{Job: job, Round: uint32(round), Device: device})
		return r.GetReport().GetJson(), err
	})
}

func (b *Bridge) AnalysisDiff(job string, from, to int, device string) (string, error) {
	if from <= 0 || to <= 0 {
		return "", wrapErr(fmt.Errorf("rondas %d y %d inválidas", from, to))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAnalysisServiceClient(c).DiffRounds(ctx, &v1.DiffRoundsRequest{Job: job, From: uint32(from), To: uint32(to), Device: device})
		return r.GetReport().GetJson(), err
	})
}

// AnalysisTimeline: around vacío = todo el trabajo; si no, RFC 3339 con ±windowSeconds.
func (b *Bridge) AnalysisTimeline(job, around string, windowSeconds int, device, pcap string) (string, error) {
	req := &v1.TimelineRequest{Job: job, Device: device, PcapPath: pcap}
	if windowSeconds > 0 {
		req.WindowSeconds = uint32(windowSeconds)
	}
	if around != "" {
		t, err := time.Parse(time.RFC3339, around)
		if err != nil {
			return "", wrapErr(fmt.Errorf("instante %q inválido: usa RFC 3339 (2026-11-04T10:09:18Z)", around))
		}
		req.Around = timestamppb.New(t)
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewAnalysisServiceClient(c).Timeline(ctx, req)
		return r.GetReport().GetJson(), err
	})
}

// Variantes con texto y claves (fase 30c): lo mismo que AnalysisRun, AnalysisDiff y AnalysisTimeline, pero con el
// texto del informe y las claves de los textos del json. Los métodos de arriba no cambian.

func (b *Bridge) AnalysisRunReport(job string, round int, device string) (ReportDTO, error) {
	if round < 0 {
		return ReportDTO{}, wrapErr(fmt.Errorf("ronda %d inválida", round))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ReportDTO, error) {
		r, err := v1.NewAnalysisServiceClient(c).AnalyzeJob(ctx, &v1.AnalyzeJobRequest{Job: job, Round: uint32(round), Device: device})
		return toReport(r.GetReport()), err
	})
}

func (b *Bridge) AnalysisDiffReport(job string, from, to int, device string) (ReportDTO, error) {
	if from <= 0 || to <= 0 {
		return ReportDTO{}, wrapErr(fmt.Errorf("rondas %d y %d inválidas", from, to))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ReportDTO, error) {
		r, err := v1.NewAnalysisServiceClient(c).DiffRounds(ctx, &v1.DiffRoundsRequest{Job: job, From: uint32(from), To: uint32(to), Device: device})
		return toReport(r.GetReport()), err
	})
}

func (b *Bridge) AnalysisTimelineReport(job, around string, windowSeconds int, device, pcap string) (ReportDTO, error) {
	req := &v1.TimelineRequest{Job: job, Device: device, PcapPath: pcap}
	if windowSeconds > 0 {
		req.WindowSeconds = uint32(windowSeconds)
	}
	if around != "" {
		t, err := time.Parse(time.RFC3339, around)
		if err != nil {
			return ReportDTO{}, wrapErr(fmt.Errorf("instante %q inválido: usa RFC 3339 (2026-11-04T10:09:18Z)", around))
		}
		req.Around = timestamppb.New(t)
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ReportDTO, error) {
		r, err := v1.NewAnalysisServiceClient(c).Timeline(ctx, req)
		return toReport(r.GetReport()), err
	})
}
