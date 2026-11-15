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
// Las líneas pueden llevar secretos (community SNMP, usuarios): por eso viaja entero por la bóveda. Se escribe en cuanto un equipo pasa a
// cambiado y se actualiza mientras la ejecución avanza (una caída del núcleo no la pierde); Ended es cero hasta que la ejecución termina.
// shortcut: no guarda huellas SSH aceptadas porque StartRun tampoco las usa (HostKeyPolicy vacía: el equipo debe estar ya en known hosts).
type pendingRec struct {
	RunID    string
	Kind     string // función del plan: ports, snippet, restore...
	Ended    time.Time
	Updated  time.Time
	Host     string
	Port     uint16
	Cred     string
	Leftover assist.Leftover
}

// base es desde cuándo cuenta la antigüedad: el fin de la ejecución o, si el núcleo cayó antes, la última vez que se escribió.
func (p pendingRec) base() time.Time {
	if p.Ended.IsZero() {
		return p.Updated
	}
	return p.Ended
}

// persister guarda y borra la reversa pendiente de una ejecución (solo la usa el hilo del motor y, ya terminado este, afterRun).
type persister struct {
	s     *assistSvc
	runID string
	t     target
	saved bool
	// failed: el fallo de guardado ya se auditó (una sola vez por ejecución, aunque la bóveda siga cerrada en cada sync)
	failed bool
	// generated: el secreto nuevo de la rotación lo generó la app; se guarda en el Leftover para que la pantalla lo diga.
	generated bool
	// rotUser y rotCred: usuario rotado y credencial de bóveda a actualizar; se guardan en el Leftover.
	rotUser, rotCred string
}

// sync es el Persist del motor: lo que sigue sin revertir (nil = nada).
func (p *persister) sync(lo *assist.Leftover) {
	if lo == nil {
		if p.saved {
			p.saved = !p.s.deletePending(p.runID)
		}
		return
	}
	p.save(lo, time.Time{}, "")
}

func (p *persister) save(lo *assist.Leftover, ended time.Time, st assist.State) {
	if p.s.isDiscarded(p.runID) {
		return
	}
	isRot := lo.Function == assist.CredRotate.Name
	lo.GeneratedSecret = p.generated && isRot
	lo.RotatedUser, lo.UpdateCredentialID = "", ""
	if isRot {
		lo.RotatedUser, lo.UpdateCredentialID = p.rotUser, p.rotCred
	}
	rec := pendingRec{RunID: p.runID, Kind: lo.Function, Ended: ended, Updated: p.s.d.Now(), Host: p.t.host, Port: p.t.port, Cred: p.t.cred, Leftover: *lo}
	if err := p.s.savePending(rec); err != nil {
		if p.failed {
			return
		}
		p.failed = true
		p.s.d.Audit("assist.pending_rollback.save_failed", rec.RunID, "the pending rollback could not be saved: "+i18n.English(err))
		return
	}
	p.saved, p.failed = true, false
	if ended.IsZero() {
		return
	}
	p.s.d.Audit("assist.pending_rollback.saved", rec.RunID, fmt.Sprintf("kind=%s state=%s devices=%d", rec.Kind, st, len(lo.Devices)))
}

// afterRun corre al terminar una ejecución, ya soltados guard y ventana. Una ejecución que terminó done (el ingeniero dejó el cambio a
// propósito) o sin equipos cambiados no deja reversa; las demás la dejan con su hora de fin. Una ejecución de reversa borra la entrada
// original si terminó bien y la conserva si no.
func (s *assistSvc) afterRun(rr *runRec, pers *persister, origin string) {
	st := rr.run.State()
	if origin != "" {
		deleted := false
		if st == assist.Done {
			deleted = s.deletePending(origin)
		}
		s.d.Audit("assist.pending_rollback.end", origin, fmt.Sprintf("run=%s state=%s deleted=%t", rr.run.ID(), st, deleted))
		return
	}
	lo := rr.run.Leftover()
	if st == assist.Done || lo == nil {
		pers.sync(nil)
		return
	}
	pers.save(lo, rr.ended, st)
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
	return v.PutReserved(vault.Credential{Label: pendingPrefix + rec.RunID, Username: "pending-rollback", Password: secret.New(raw)})
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

func (s *assistSvc) isDiscarded(runID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.discarded[runID]
}

// reversing dice si hay una ejecución de reversa de la entrada de runID que todavía no cerró: se mira finished y no
// run.Done(), que se cierra antes de que afterRun borre la entrada de una reversa completada.
func (s *assistSvc) reversing(runID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rr := range s.runs {
		if rr.origin != runID {
			continue
		}
		select {
		case <-rr.finished:
		default:
			return true
		}
	}
	return false
}

// live dice si la ejecución sigue viva en este núcleo (su reversa no se ofrece hasta que termine).
func (s *assistSvc) live(runID string) bool {
	s.mu.Lock()
	rr, ok := s.runs[runID]
	s.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case <-rr.run.Done():
		return false
	default:
		return true
	}
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
		id := strings.TrimPrefix(in.Label, pendingPrefix)
		if s.live(id) || s.reversing(id) { // con su ejecución o su reversa en curso, el núcleo rechaza aplicarla o descartarla
			continue
		}
		rec, err := s.loadPending(in.Label)
		if err != nil { // una entrada ilegible no tumba la lista: se muestra para poder descartarla
			out.Rollbacks = append(out.Rollbacks, &v1.PendingRollback{RunId: id, Unreadable: true})
			continue
		}
		pr := &v1.PendingRollback{RunId: rec.RunID, Kind: rec.Kind, EndedUnix: rec.base().Unix(), AgeSeconds: int64(now.Sub(rec.base()).Seconds()), WriteMemory: rec.Leftover.WriteMemory, GeneratedSecret: rec.Leftover.GeneratedSecret, RotatedUser: rec.Leftover.RotatedUser, UpdateCredentialId: rec.Leftover.UpdateCredentialID}
		for _, d := range rec.Leftover.Devices {
			pr.Devices = append(pr.Devices, &v1.PendingRollbackDevice{Device: d.Device, RollbackLines: assist.ScrubLines(d.Rollback, d.Secrets, rec.Leftover.Scrub), Provisional: d.Provisional})
		}
		out.Rollbacks = append(out.Rollbacks, pr)
	}
	sort.SliceStable(out.Rollbacks, func(i, j int) bool { return out.Rollbacks[i].EndedUnix > out.Rollbacks[j].EndedUnix })
	return out, nil
}

// DiscardPendingRollback borra una reversa pendiente (también una ilegible) sin aplicarla.
func (s *assistSvc) DiscardPendingRollback(ctx context.Context, r *v1.DiscardPendingRollbackRequest) (*v1.DiscardPendingRollbackResponse, error) {
	s.d.MarkActive()
	if err := s.vault(ctx); err != nil {
		return nil, err
	}
	if s.live(r.RunId) {
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.reversa_en_curso", i18n.A("id", r.RunId))
	}
	if s.reversing(r.RunId) {
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.reversa_aplicandose", i18n.A("id", r.RunId))
	}
	s.mu.Lock()
	s.discarded[r.RunId] = true // antes de borrar: una ejecución que justo termina no la vuelve a guardar
	s.mu.Unlock()
	if err := s.d.Vault().DeleteReserved(pendingPrefix + r.RunId); err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return nil, service.Err(ctx, codes.NotFound, "assist.svc.reversa_no_existe", i18n.A("id", r.RunId))
		}
		return nil, service.VaultErr(ctx, err)
	}
	s.d.Audit("assist.pending_rollback.discard", r.RunId, "discarded by the engineer")
	return &v1.DiscardPendingRollbackResponse{}, nil
}

// StartPendingRollback aplica la reversa guardada como una ejecución asistida nueva: confirmación por paso, sin write memory, y con el
// estado en que la ejecución dejó el equipo como pre-check (si ya no coincide, no se manda nada).
func (s *assistSvc) StartPendingRollback(ctx context.Context, r *v1.StartPendingRollbackRequest) (*v1.StartPendingRollbackResponse, error) {
	s.d.MarkActive()
	// Regla 1 del ADR 0007: sin assisted explícito no se conecta ni se cambia nada.
	if !r.Assisted {
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.el_modo_asistido_esta_apagado", nil)
	}
	if s.ctx.Err() != nil {
		return nil, service.Err(ctx, codes.Unavailable, "assist.svc.el_nucleo_se_esta_cerrando", nil)
	}
	if err := s.vault(ctx); err != nil {
		return nil, err
	}
	if s.live(r.RunId) {
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.reversa_en_curso", i18n.A("id", r.RunId))
	}
	if s.reversing(r.RunId) { // como Discard y List: su reversa ya corre
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.reversa_ya_aplicandose", i18n.A("id", r.RunId))
	}
	rec, err := s.loadPending(pendingPrefix + r.RunId)
	if err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			return nil, service.Err(ctx, codes.NotFound, "assist.svc.reversa_no_existe", i18n.A("id", r.RunId))
		}
		return nil, service.Err(ctx, codes.Internal, "assist.svc.reversa_ilegible", i18n.A("id", r.RunId, "cause", err.Error()))
	}
	age := s.d.Now().Sub(rec.base())
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
	keys := []string{lockKey(rec.Host, rec.Port, "*")}
	runID, err := s.launch(ctx, pr, "", keys, rec.RunID)
	if err != nil {
		return nil, err
	}
	s.d.Audit("assist.pending_rollback.start", rec.RunID, fmt.Sprintf("run=%s kind=%s age=%s accept_age=%t devices=%s", runID, rec.Kind, age.Round(time.Second), r.AcceptAge, strings.Join(pr.devices, ",")))
	return &v1.StartPendingRollbackResponse{RunId: runID}, nil
}
