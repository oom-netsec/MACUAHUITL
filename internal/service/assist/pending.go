package assist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/assist"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// pendingMaxAge: pasado este tiempo desde el fin de la ejecución, aplicar la reversa exige accept_age.
const pendingMaxAge = 24 * time.Hour

// pendingPrefix es la etiqueta reservada de la bóveda; el ID de la ejecución va al final.
const pendingPrefix = vault.ReservedPrefix + "reversa-pendiente:"

// pendingRec es lo que se guarda (cifrado, como secreto de una entrada reservada) de una ejecución que dejó equipos cambiados.
// Las líneas pueden llevar secretos (community SNMP, usuarios): por eso viaja entero por la bóveda.
// shortcut: no guarda huellas SSH aceptadas porque StartRun tampoco las usa (HostKeyPolicy vacía: el equipo debe estar ya en known hosts).
type pendingRec struct {
	RunID    string
	Kind     string // función del plan: ports, snippet, restore...
	Ended    time.Time
	Host     string
	Port     uint16
	Cred     string
	Label    string
	Scrub    bool
	Leftover assist.Leftover
}

// afterRun corre al terminar una ejecución, ya soltados guard y ventana. Una ejecución normal que dejó equipos cambiados guarda su reversa;
// una ejecución de reversa borra la entrada si terminó bien y la conserva si no.
func (s *assistSvc) afterRun(rr *runRec, t target, origin string) {
	st := rr.run.State()
	if origin != "" {
		deleted := false
		if st == assist.Done {
			deleted = s.deletePending(origin)
		}
		s.d.Audit("assist.pending_rollback.end", origin, fmt.Sprintf("run=%s state=%s deleted=%t", rr.run.ID(), st, deleted))
		return
	}
	if st != assist.Aborted && st != assist.Failed && st != assist.Abandoned {
		return
	}
	lo := rr.run.Leftover()
	if lo == nil {
		return
	}
	rec := pendingRec{RunID: rr.run.ID(), Kind: lo.Function, Ended: rr.ended, Host: t.host, Port: t.port, Cred: t.cred, Leftover: *lo}
	if err := s.savePending(rec); err != nil {
		s.d.Audit("assist.pending_rollback.save_failed", rec.RunID, "the pending rollback could not be saved: "+i18n.English(err))
		return
	}
	s.d.Audit("assist.pending_rollback.saved", rec.RunID, fmt.Sprintf("kind=%s state=%s devices=%d", rec.Kind, st, len(lo.Devices)))
}

func (s *assistSvc) savePending(rec pendingRec) error {
	v := s.d.Vault()
	if v == nil || !v.Unlocked() {
		return vault.ErrLocked
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = v.Put(vault.Credential{Label: pendingPrefix + rec.RunID, Username: "pending-rollback", Password: secret.New(raw)})
	return err
}

func (s *assistSvc) deletePending(runID string) bool {
	v := s.d.Vault()
	if v == nil || !v.Unlocked() {
		return false
	}
	return v.DeleteReserved(pendingPrefix+runID) == nil
}

// loadPending lee y descifra una reversa pendiente.
func (s *assistSvc) loadPending(label string) (pendingRec, error) {
	c, err := s.d.Vault().GetReserved(label)
	if err != nil {
		return pendingRec{}, err
	}
	defer c.Password.Destroy()
	defer c.Enable.Destroy()
	defer c.SSHKey.Destroy()
	var rec pendingRec
	return rec, json.Unmarshal(c.Password.Bytes(), &rec)
}

func (s *assistSvc) ListPendingRollbacks(ctx context.Context, _ *v1.ListPendingRollbacksRequest) (*v1.ListPendingRollbacksResponse, error) {
	s.d.MarkActive()
	if err := s.vault(ctx); err != nil {
		return nil, err
	}
	infos, err := s.d.Vault().ListAll()
	if err != nil {
		return nil, service.VaultErr(ctx, err)
	}
	out := &v1.ListPendingRollbacksResponse{}
	now := s.d.Now()
	for _, in := range infos {
		if !strings.HasPrefix(in.Label, pendingPrefix) {
			continue
		}
		rec, err := s.loadPending(in.Label)
		if err != nil {
			return nil, service.Err(ctx, codes.Internal, "assist.svc.reversa_ilegible", i18n.A("id", strings.TrimPrefix(in.Label, pendingPrefix), "cause", err.Error()))
		}
		pr := &v1.PendingRollback{RunId: rec.RunID, Kind: rec.Kind, EndedUnix: rec.Ended.Unix(), AgeSeconds: int64(now.Sub(rec.Ended).Seconds())}
		for _, d := range rec.Leftover.Devices {
			pr.Devices = append(pr.Devices, &v1.PendingRollbackDevice{Device: d.Device, RollbackLines: assist.ScrubLines(d.Rollback, d.Secrets, rec.Leftover.Scrub)})
		}
		out.Rollbacks = append(out.Rollbacks, pr)
	}
	sort.Slice(out.Rollbacks, func(i, j int) bool { return out.Rollbacks[i].EndedUnix > out.Rollbacks[j].EndedUnix })
	return out, nil
}

// StartPendingRollback aplica la reversa guardada como una ejecución asistida nueva: confirmación por paso, sin write memory, y con el
// estado en que la ejecución dejó el equipo como pre-check (si ya no coincide, no se manda nada).
func (s *assistSvc) StartPendingRollback(ctx context.Context, r *v1.StartPendingRollbackRequest) (*v1.StartPendingRollbackResponse, error) {
	s.d.MarkActive()
	if s.ctx.Err() != nil {
		return nil, service.Err(ctx, codes.Unavailable, "assist.svc.el_nucleo_se_esta_cerrando", nil)
	}
	if err := s.vault(ctx); err != nil {
		return nil, err
	}
	rec, err := s.loadPending(pendingPrefix + r.RunId)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return nil, service.Err(ctx, codes.NotFound, "assist.svc.reversa_no_existe", i18n.A("id", r.RunId))
		}
		return nil, service.Err(ctx, codes.Internal, "assist.svc.reversa_ilegible", i18n.A("id", r.RunId, "cause", err.Error()))
	}
	age := s.d.Now().Sub(rec.Ended)
	if age > pendingMaxAge && !r.AcceptAge {
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.reversa_vieja", i18n.A("age", age.Round(time.Minute).String()))
	}
	plan, fn, err := assist.RollbackPlan(rec.Leftover)
	if err != nil {
		return nil, service.ErrFrom(ctx, codes.FailedPrecondition, err)
	}
	if err := assist.Validate(plan, fn); err != nil {
		return nil, service.ErrFrom(ctx, codes.InvalidArgument, err)
	}
	label := plan.Devices[0].Device
	pr := &planRec{plan: plan, fn: fn, label: label, t: target{host: rec.Host, port: rec.Port, cred: rec.Cred}}
	for _, d := range plan.Devices {
		pr.devices = append(pr.devices, d.Device)
	}
	// Una reversa pendiente toca varios objetos de un equipo: un solo candado del equipo entero, como restaurar.
	keys := []string{strings.ToLower(fmt.Sprintf("%s:%d|*", rec.Host, rec.Port))}
	runID, err := s.launch(ctx, pr, "", keys, rec.RunID)
	if err != nil {
		return nil, err
	}
	s.d.Audit("assist.pending_rollback.start", rec.RunID, fmt.Sprintf("run=%s kind=%s age=%s accept_age=%t devices=%s", runID, rec.Kind, age.Round(time.Second), r.AcceptAge, strings.Join(pr.devices, ",")))
	return &v1.StartPendingRollbackResponse{RunId: runID}, nil
}
