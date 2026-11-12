package bridge

import (
	"context"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ---- Respaldos de configuración (Fase 16b): solo lectura, un trabajo de Patrol ----

type BackupStartDTO struct {
	JobID  string `json:"jobId"`
	Armed  bool   `json:"armed"`
	Detail string `json:"detail"`
}

type BackupCollectDTO struct {
	State string `json:"state"`
	Done  bool   `json:"done"`
	Error string `json:"error"`
	Json  string `json:"json"`
	Text  string `json:"text"`
}

type BackupGetDTO struct {
	Meta string `json:"meta"`
	Text string `json:"text"`
}

// BackupStart crea y arma el respaldo; con intervalSeconds > 0 queda programado (rounds veces).
func (b *Bridge) BackupStart(targets []AdhocTargetDTO, credentialID string, startup bool, keep, intervalSeconds, rounds uint32, secrets bool, accept []string) (BackupStartDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (BackupStartDTO, error) {
		req := &v1.StartBackupRequest{CredentialId: credentialID, Startup: startup, Keep: keep, IntervalSeconds: intervalSeconds, Rounds: rounds, IncludeSecrets: secrets, AcceptedHostKeyFingerprints: accept}
		for _, t := range targets {
			req.Targets = append(req.Targets, &v1.Target{Address: t.Address, Port: t.Port})
		}
		r, err := v1.NewBackupServiceClient(c).StartBackup(ctx, req)
		return BackupStartDTO{JobID: r.GetJobId(), Armed: r.GetArmed(), Detail: r.GetDetail()}, err
	})
}

func (b *Bridge) BackupCollect(jobID string) (BackupCollectDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (BackupCollectDTO, error) {
		r, err := v1.NewBackupServiceClient(c).CollectBackups(ctx, &v1.CollectBackupsRequest{JobId: jobID})
		return BackupCollectDTO{State: r.GetState(), Done: r.GetDone(), Error: r.GetError(), Json: r.GetReport().GetJson(), Text: r.GetReport().GetText()}, err
	})
}

// BackupList devuelve el JSON {backups:[…], masked}; device vacío = todos.
func (b *Bridge) BackupList(device string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewBackupServiceClient(c).ListBackups(ctx, &v1.ListBackupsRequest{Device: device})
		return r.GetReport().GetJson(), err
	})
}

func (b *Bridge) BackupGet(id string) (BackupGetDTO, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (BackupGetDTO, error) {
		r, err := v1.NewBackupServiceClient(c).GetBackup(ctx, &v1.GetBackupRequest{Id: id})
		return BackupGetDTO{Meta: r.GetMetaJson(), Text: r.GetText()}, err
	})
}

func (b *Bridge) BackupDiff(from, to string) (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewBackupServiceClient(c).DiffBackups(ctx, &v1.DiffBackupsRequest{From: from, To: to})
		return r.GetReport().GetJson(), err
	})
}
