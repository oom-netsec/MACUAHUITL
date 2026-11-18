package core

import (
	"context"
	"fmt"
	"slices"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// addPinned registra una fuente de trabajos «en uso» (como addBusy): los servicios que todavía necesitan un job por id
// aunque ya no corra (respaldo, cambio, ad-hoc) devuelven aquí sus ids con el motivo.
func (c *Core) addPinned(f func() []service.PinnedJob) {
	c.mu.Lock()
	c.pinned = append(c.pinned, f)
	c.mu.Unlock()
}

// pinnedSet es el conjunto «en uso». Se calcula SIN c.mu: las fuentes toman sus propios mutex.
func (c *Core) pinnedSet() map[string]string {
	c.mu.Lock()
	srcs := slices.Clone(c.pinned)
	c.mu.Unlock()
	out := map[string]string{}
	for _, f := range srcs {
		for _, p := range f() {
			out[p.ID] = p.Reason
		}
	}
	return out
}

// isActive: armed, arming (con o sin paused) y todo terminal que aún no cerró (en finish). No se usa closing: nunca vuelve a false.
// Requiere c.mu.
func (j *job) isActive() bool {
	return j.state == "armed" || j.state == "arming" || isFinal(j.state) && !j.closed
}

// quitado es lo que se audita de un job quitado.
type quitado struct {
	j                *job
	name, dir, state string
	finished         string
	root             string
}

// removeJobs quita ids del historial (memoria y base); nunca toca disco. Los activos y los «en uso» no se quitan:
// salen en skipped con su motivo; los ids que no existen se ignoran. reason es el de la auditoría (manual,
// clear_finished, age_7d: este último audita job.pruned, para la poda de 46d).
// Orden de locks: persistMu del job y luego c.mu; los ids van ordenados para que dos quitas no se crucen.
func (c *Core) removeJobs(ids []string, reason string) (removed []string, skipped []*v1.SkippedJob, err error) {
	ids = slices.Compact(slices.Sorted(slices.Values(ids)))
	pins := c.pinnedSet() // antes de tomar c.mu
	var done []quitado
	for _, id := range ids {
		c.mu.Lock()
		j, ok := c.jobs[id]
		c.mu.Unlock()
		if !ok {
			continue
		}
		j.persistMu.Lock()
		c.mu.Lock()
		if c.jobs[id] != j { // otro lo quitó mientras esperábamos
			c.mu.Unlock()
			j.persistMu.Unlock()
			continue
		}
		why := pins[id]
		if j.isActive() {
			why = "active"
		}
		if why != "" {
			c.mu.Unlock()
			j.persistMu.Unlock()
			skipped = append(skipped, &v1.SkippedJob{JobId: id, Reason: why})
			continue
		}
		j.removed = true
		delete(c.jobs, id)
		q := quitado{j: j, name: j.spec.Name, dir: j.OutputDir, state: j.state, root: j.spec.OutputDir}
		if q.dir == "" {
			q.dir = j.spec.OutputDir
		}
		if !j.FinishedAt.IsZero() {
			q.finished = j.FinishedAt.UTC().Format(time.RFC3339)
		}
		c.mu.Unlock() // persistMu sigue tomado hasta cerrar la tx
		done = append(done, q)
	}
	if len(done) > 0 {
		err = c.deleteJobs(done)
	}
	// La tx ya está cerrada. Si falló, los jobs vuelven a memoria antes de soltar persistMu.
	for _, q := range done {
		if err != nil {
			c.mu.Lock()
			q.j.removed = false
			c.jobs[q.j.id] = q.j
			c.mu.Unlock()
		}
		q.j.persistMu.Unlock()
	}
	// Auditoría: sin locks, sin tx ni rows abiertas (una sola conexión).
	action := "job.removed"
	if reason == "age_7d" {
		action = "job.pruned"
	}
	for _, q := range done {
		if err != nil {
			c.audit("job.remove_failed", q.j.id, i18n.English(err))
			continue
		}
		removed = append(removed, q.j.id)
		c.audit(action, q.j.id, fmt.Sprintf("name=%q dir=%q state=%s finished=%s reason=%s", q.name, q.dir, q.state, q.finished, reason))
	}
	if err != nil {
		return nil, nil, err
	}
	return removed, skipped, nil
}

// deleteJobs borra las filas del lote y guarda sus raíces en una sola tx corta (foreign_keys: hijos primero).
func (c *Core) deleteJobs(done []quitado) error {
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	for _, q := range done {
		for _, st := range []string{`DELETE FROM run_devices WHERE job_id=?`, `DELETE FROM job_runs WHERE job_id=?`, `DELETE FROM jobs WHERE id=?`} {
			if _, err := tx.Exec(st, q.j.id); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := service.RecordJobRoot(tx, q.root); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// RemoveJobs quita trabajos del historial: por ids o todos los terminados. Nunca falla por activos ni en uso.
func (s *patrolSvc) RemoveJobs(ctx context.Context, r *v1.RemoveJobsRequest) (*v1.RemoveJobsResponse, error) {
	c := s.c
	if len(r.JobIds) > 0 == r.AllFinished {
		return nil, service.Err(ctx, codes.InvalidArgument, "patrol.err.remove_args", nil)
	}
	c.markActive()
	ids, reason := r.JobIds, "manual"
	if r.AllFinished {
		reason = "clear_finished"
		c.mu.Lock()
		for id, j := range c.jobs {
			if isFinal(j.state) { // los activos entran para salir en skipped; un created no es «terminado»
				ids = append(ids, id)
			}
		}
		c.mu.Unlock()
	}
	removed, skipped, err := c.removeJobs(ids, reason)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &v1.RemoveJobsResponse{Removed: int32(len(removed)), RemovedIds: removed, Skipped: skipped}, nil
}
