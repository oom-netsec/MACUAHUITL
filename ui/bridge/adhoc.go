package bridge

import (
	"context"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Ejecutor ad-hoc (Fase 16a): lote de solo lectura como trabajo de Patrol ----

type AdhocTargetDTO struct {
	Address string `json:"address"`
	Port    uint32 `json:"port"`
}

type AdhocStartDTO struct {
	JobID  string `json:"jobId"`
	Armed  bool   `json:"armed"`
	Detail string `json:"detail"`
}

type AdhocResultDTO struct {
	State    string `json:"state"`
	Done     bool   `json:"done"`
	Json     string `json:"json"`
	Text     string `json:"text"`
	Csv      string `json:"csv"`
	Markdown string `json:"markdown"`
	Error    string `json:"error"`
}

// AdhocStart crea y arma el lote; si no se arma (llave de host nueva, bóveda), Detail dice por qué.
func (b *Bridge) AdhocStart(targets []AdhocTargetDTO, credentialID, commands string, accept []string) (AdhocStartDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (AdhocStartDTO, error) {
		req := &v1.StartAdhocRequest{CredentialId: credentialID, Commands: commands, AcceptedHostKeyFingerprints: accept}
		for _, t := range targets {
			req.Targets = append(req.Targets, &v1.Target{Address: t.Address, Port: t.Port})
		}
		r, err := v1.NewAdhocServiceClient(c).StartAdhoc(ctx, req)
		return AdhocStartDTO{JobID: r.GetJobId(), Armed: r.GetArmed(), Detail: r.GetDetail()}, err
	})
}

func (b *Bridge) AdhocResult(jobID string) (AdhocResultDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (AdhocResultDTO, error) {
		r, err := v1.NewAdhocServiceClient(c).AdhocResult(ctx, &v1.AdhocResultRequest{JobId: jobID})
		return AdhocResultDTO{State: r.GetState(), Done: r.GetDone(), Json: r.GetReport().GetJson(), Text: r.GetReport().GetText(), Csv: r.GetCsv(), Markdown: r.GetMarkdown(), Error: r.GetError()}, err
	})
}
