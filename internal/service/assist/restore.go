package assist

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/assist"
	"github.com/oom-netsec/MACUAHUITL/internal/backup"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// PlanRestore arma el plan de restaurar por diff un respaldo de internal/backup. Solo lee: el respaldo del disco y el running-config del
// equipo. Un respaldo enmascarado, alterado o de otro equipo se rechaza; lo que el diff tocaría y la lista cerrada no admite sale en
// `refused` (el plan se rechaza entero, salvo con allow_partial) y nada se guarda para ejecutar.
func (s *assistSvc) PlanRestore(ctx context.Context, r *v1.PlanRestoreRequest) (*v1.PlanRestoreResponse, error) {
	s.d.MarkActive()
	if err := checkTarget(ctx, r.Target); err != nil {
		return nil, err
	}
	if r.MaxLines > assist.MaxRestoreLines {
		return nil, service.Err(ctx, codes.InvalidArgument, "assist.svc.el_tope_de_lineas_va", i18n.A("max", assist.MaxRestoreLines))
	}
	e, text, err := backup.Store{Root: filepath.Join(s.d.Outputs(), "respaldos")}.Get(r.BackupId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if e.Kind != backup.Running { // el diff es contra el running-config del equipo
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.el_respaldo_es_de_solo", i18n.A("backup", r.BackupId, "kind", e.Kind))
	}
	if e.Masked { // antes de conectar: un respaldo enmascarado borraría contraseñas y llaves
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.el_respaldo_se_tomo_con", i18n.A("backup", r.BackupId))
	}
	// La ficha dice con qué hash se guardó: un archivo cambiado después no se restaura.
	if sum := sha256.Sum256([]byte(text)); e.SHA256 == "" || e.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.el_respaldo_no_coincide_con", i18n.A("backup", r.BackupId))
	}
	// La ficha debe traer la firma de la llave de la bóveda: sin ella (respaldo viejo, ficha editada o de otra bóveda) se puede ver y comparar, no restaurar.
	key, err := service.BackupKey(s.d.Vault(), false)
	if err != nil && !errors.Is(err, vault.ErrNotFound) {
		return nil, service.VaultErr(ctx, err)
	}
	if err != nil || !e.Verify(key) {
		return nil, service.Err(ctx, codes.FailedPrecondition, "assist.svc.el_respaldo_no_tiene_una", i18n.A("backup", r.BackupId))
	}
	ch := assist.RestoreChange{Backup: text, BackupMasked: e.Masked, Management: r.ManagementInterface, BackupSerial: e.Serial, BackupTruncated: e.Truncated,
		MaxLines: int(r.MaxLines), Partial: r.AllowPartial}
	var rp assist.RestorePlan
	var buildErr error
	var fn assist.Function
	id, plan, err := s.planWith(ctx, r.Target, r.AcceptedHostKeyFingerprints, assist.RestoreDiffPre(), assist.RestoreEgressPre, &fn, nil, r.WriteMemory,
		fmt.Sprintf("backup=%s partial=%t", r.BackupId, r.AllowPartial), nil,
		func(label string, outs map[string]string) (assist.DevicePlan, error) {
			rp, buildErr = assist.RestoreDiffPlan(label, ch, outs)
			fn = rp.Fn
			return rp.Device, buildErr
		})
	if err != nil {
		if buildErr != nil && len(rp.Refused) > 0 && errors.Is(buildErr, assist.ErrRestoreRefused) {
			s.d.Audit("assist.plan.refused", r.Target.Address, fmt.Sprintf("function=%s backup=%s refused=%d", assist.RestoreDiff, r.BackupId, len(rp.Refused)))
			return &v1.PlanRestoreResponse{Refused: refusalsToProto(i18n.Locale(ctx), rp.Refused), Reason: coded(ctx, buildErr)}, nil
		}
		return nil, err
	}
	return &v1.PlanRestoreResponse{PlanId: id, Plan: planToProto(i18n.Locale(ctx), assist.Redact(plan, fn)), Refused: refusalsToProto(i18n.Locale(ctx), rp.Refused)}, nil
}

func refusalsToProto(loc string, rs []assist.Refusal) []*v1.RestoreRefusal {
	var out []*v1.RestoreRefusal
	for _, r := range rs {
		out = append(out, &v1.RestoreRefusal{Path: r.Path, Line: r.Line, Why: refusalWhy(loc, r)})
	}
	return out
}

// refusalWhy es el motivo de una negativa en el idioma pedido (con es, el de siempre).
func refusalWhy(loc string, r assist.Refusal) string {
	if r.WhyT.Empty() {
		return r.Why
	}
	return r.WhyT.In(loc)
}
