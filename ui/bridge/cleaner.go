package bridge

import (
	"context"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Limpiador de configuraciones (Fase 16a): trabaja sobre el texto pegado ----

type CleanerDTO struct {
	Json   string                `json:"json"`
	Text   string                `json:"text"`
	Output string                `json:"output"`
	Keys   map[string]KeyArgsDTO `json:"keys,omitempty"` // claves de los textos del json (fase 30c)
}

func (b *Bridge) CleanerRun(text string, sort bool) (CleanerDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (CleanerDTO, error) {
		r, err := v1.NewCleanerServiceClient(c).Clean(ctx, &v1.CleanRequest{Text: text, Sort: sort})
		return CleanerDTO{Json: r.GetReport().GetJson(), Text: r.GetReport().GetText(), Output: r.GetOutput(), Keys: reportKeys(r.GetReport())}, err
	})
}
