package core

import (
	"context"
	"database/sql"
	"io"
	"path/filepath"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// coreDeps es lo que el núcleo presta a los servicios de área (service.Deps): una vista
// angosta de Core, sin jobs, bus ni mutex.
type coreDeps struct{ c *Core }

func (d coreDeps) Audit(action, target, detail string) { d.c.audit(action, target, detail) }
func (d coreDeps) ExportAudit(ctx context.Context, w io.Writer, from, to time.Time) error {
	return d.c.log.Export(ctx, w, from, to)
}
func (d coreDeps) MarkActive()                                { d.c.markActive() }
func (d coreDeps) Now() time.Time                             { return d.c.o.Now() }
func (d coreDeps) Guard() *transport.Guard                    { return d.c.guard }
func (d coreDeps) DB() *sql.DB                                { return d.c.db }
func (d coreDeps) Outputs() string                            { return d.c.settings.Outputs() }
func (d coreDeps) Settings() *service.CoreSettings            { return d.c.settings }
func (d coreDeps) DiagLookPath() func(string) (string, error) { return d.c.o.DiagLookPath }
func (d coreDeps) Hosts() *transport.KnownHosts               { return d.c.hosts }
func (d coreDeps) OnClose(f func()) {
	d.c.mu.Lock()
	d.c.closers = append(d.c.closers, f)
	d.c.mu.Unlock()
}
func (d coreDeps) Patrol() v1.PatrolServiceServer { return &patrolSvc{c: d.c} }
func (d coreDeps) ValidateJob(ctx context.Context, p *v1.JobSpec) error {
	_, err := (&patrolSvc{c: d.c}).validate(ctx, p)
	return err
}

func (d coreDeps) Vault() *vault.Vault {
	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	return d.c.vault
}

func (d coreDeps) SealParams() vault.Params {
	if d.c.o.VaultParams != nil {
		return *d.c.o.VaultParams
	}
	return vault.DefaultParams
}

func (d coreDeps) Job(id string) (service.JobInfo, error) {
	j, err := d.c.getJob(id)
	if err != nil {
		return service.JobInfo{}, err
	}
	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	info := service.JobInfo{State: j.state, FinishErr: j.FinishErr}
	switch {
	case j.writer != nil:
		info.Dir = j.writer.Dir()
	case filepath.IsAbs(j.OutputDir): // trabajo recargado: sin escritor, pero con la carpeta del historial
		info.Dir = j.OutputDir
	}
	return info, nil
}
