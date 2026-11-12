package bridge

import (
	"context"
	"fmt"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Deriva de configuración (Fase 16a): solo lee la carpeta de un trabajo ----

// DriftRun devuelve el JSON del reporte; la UI pinta los cambios por equipo.
func (b *Bridge) DriftRun(job string, round int, device string) (string, error) {
	if round < 0 {
		return "", wrapErr(fmt.Errorf("ronda %d inválida", round))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewDriftServiceClient(c).Drift(ctx, &v1.DriftRequest{Job: job, Round: uint32(round), Device: device})
		return r.GetReport().GetJson(), err
	})
}

// DriftRunReport es DriftRun con el texto del informe y las claves de los textos del json (fase 30c).
func (b *Bridge) DriftRunReport(job string, round int, device string) (ReportDTO, error) {
	if round < 0 {
		return ReportDTO{}, wrapErr(fmt.Errorf("ronda %d inválida", round))
	}
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (ReportDTO, error) {
		r, err := v1.NewDriftServiceClient(c).Drift(ctx, &v1.DriftRequest{Job: job, Round: uint32(round), Device: device})
		return toReport(r.GetReport()), err
	})
}
