// Package metrics es el servicio gRPC de datos para gráficas y la vista de frente del switch
// (fase 19): series de un trabajo de Patrol y estado de puertos. Solo lectura.
package metrics

import (
	"context"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/metrics"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

type svc struct {
	v1.UnimplementedMetricsServiceServer
	d service.Deps
}

// Module registra el servicio de métricas.
type Module struct{}

func (Module) Register(s ipc.Registrar, d service.Deps) {
	v1.RegisterMetricsServiceServer(s, &svc{d: d})
}

// jobDir resuelve la carpeta de salida de un trabajo por su ID o por una ruta absoluta.
func (s *svc) jobDir(jobID, dir string) (string, error) {
	if jobID != "" {
		j, err := s.d.Job(jobID)
		if err != nil {
			return "", err
		}
		if j.Dir == "" {
			return "", status.Error(codes.FailedPrecondition, "el trabajo aún no tiene salidas")
		}
		return j.Dir, nil
	}
	if dir == "" {
		return "", status.Error(codes.InvalidArgument, "indica un trabajo o una carpeta de salida")
	}
	if !filepath.IsAbs(dir) {
		return "", status.Errorf(codes.InvalidArgument, "la ruta %q debe ser absoluta", dir)
	}
	return dir, nil
}

func (s *svc) GetJobMetrics(_ context.Context, r *v1.GetJobMetricsRequest) (*v1.GetJobMetricsResponse, error) {
	s.d.MarkActive()
	if r.MaxPoints < 0 || r.MaxInterfaces < 0 || len(r.Interfaces) > metrics.MaxIfaces {
		return nil, status.Error(codes.InvalidArgument, "topes inválidos")
	}
	dir, err := s.jobDir(r.JobId, r.Dir)
	if err != nil {
		return nil, err
	}
	s.d.Audit("metrics.job", dir, "equipo="+r.Device+" interfaces="+strings.Join(r.Interfaces, ","))
	res, err := metrics.Build(dir, metrics.Options{Device: r.Device, MaxPoints: int(r.MaxPoints), MaxIfaces: int(r.MaxInterfaces), Ifaces: r.Interfaces})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return toProto(res), nil
}

func toProto(res metrics.Result) *v1.GetJobMetricsResponse {
	out := &v1.GetJobMetricsResponse{Warnings: res.Warnings}
	for _, d := range res.Devices {
		m := &v1.DeviceMetrics{Address: d.Address, Hostname: d.Hostname, Rounds: int32(d.Rounds), InterfaceTotal: int32(d.IfaceTotal), Truncated: d.Truncated, Warnings: d.Warnings}
		for _, p := range d.CPU {
			m.Cpu = append(m.Cpu, &v1.CpuPoint{Round: int32(p.Round), AtMs: p.At.UnixMilli(), FiveSec: p.Five, OneMin: p.OneMin, FiveMin: p.FiveMin})
		}
		for _, s := range d.Memory {
			ms := &v1.MemorySeries{Pool: s.Pool}
			for _, p := range s.Points {
				ms.Points = append(ms.Points, &v1.MemoryPoint{Round: int32(p.Round), AtMs: p.At.UnixMilli(), Used: p.Used, Free: p.Free, Total: p.Total})
			}
			m.Memory = append(m.Memory, ms)
		}
		for _, s := range d.Interfaces {
			is := &v1.InterfaceSeries{Name: s.Name, Description: s.Description, BwKbit: s.BWKbit, PeakUtilPct: s.PeakUtilPct}
			for _, p := range s.Points {
				is.Points = append(is.Points, &v1.InterfacePoint{Round: int32(p.Round), AtMs: p.At.UnixMilli(), InBps: p.InBps, OutBps: p.OutBps, Source: p.Source,
					InUtilPct: p.InUtilPct, OutUtilPct: p.OutUtilPct, DeltaOk: p.DeltaOK, InErrors: p.InErrors, OutErrors: p.OutErrors, Crc: p.CRC,
					Resets: p.Resets, InDrops: p.InDrops, OutDrops: p.OutDrops, Reboot: p.Reboot})
			}
			m.Interfaces = append(m.Interfaces, is)
		}
		for _, b := range d.Reboots {
			m.Reboots = append(m.Reboots, &v1.RebootEvent{Round: int32(b.Round), BootMs: b.At.UnixMilli()})
		}
		out.Devices = append(out.Devices, m)
	}
	return out
}
