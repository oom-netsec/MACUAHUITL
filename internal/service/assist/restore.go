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
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// PlanRestore arma el plan de restaurar por diff un respaldo de internal/backup. Solo lee: el respaldo del disco y el running-config del
// equipo. Un respaldo enmascarado, alterado o de otro equipo se rechaza; lo que el diff tocaría y la lista cerrada no admite sale en
// `refused` (el plan se rechaza entero, salvo con allow_partial) y nada se guarda para ejecutar.
func (s *assistSvc) PlanRestore(ctx context.Context, r *v1.PlanRestoreRequest) (*v1.PlanRestoreResponse, error) {
	s.d.MarkActive()
	if err := checkTarget(r.Target); err != nil {
		return nil, err
	}
	if r.MaxLines > assist.MaxRestoreLines {
		return nil, status.Errorf(codes.InvalidArgument, "el tope de líneas va de 1 a %d", assist.MaxRestoreLines)
	}
	e, text, err := backup.Store{Root: filepath.Join(s.d.Outputs(), "respaldos")}.Get(r.BackupId)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if e.Kind != backup.Running { // el diff es contra el running-config del equipo
		return nil, status.Errorf(codes.FailedPrecondition, "el respaldo %s es de %s: solo se restaura un respaldo de running-config", r.BackupId, e.Kind)
	}
	if e.Masked { // antes de conectar: un respaldo enmascarado borraría contraseñas y llaves
		return nil, status.Errorf(codes.FailedPrecondition, "el respaldo %s se tomó con secretos enmascarados: restaurarlo borraría contraseñas y llaves; toma uno sin enmascarar", r.BackupId)
	}
	// La ficha dice con qué hash se guardó: un archivo cambiado después no se restaura.
	if sum := sha256.Sum256([]byte(text)); e.SHA256 == "" || e.SHA256 != hex.EncodeToString(sum[:]) {
		return nil, status.Errorf(codes.FailedPrecondition, "el respaldo %s no coincide con su ficha (cambió después de guardarse o no tiene ficha): no se restaura", r.BackupId)
	}
	// La ficha debe traer la firma de la llave de la bóveda: sin ella (respaldo viejo, ficha editada o de otra bóveda) se puede ver y comparar, no restaurar.
	key, err := service.BackupKey(s.d.Vault(), false)
	if err != nil && !errors.Is(err, vault.ErrNotFound) {
		return nil, service.VaultErr(err)
	}
	if err != nil || !e.Verify(key) {
		return nil, status.Errorf(codes.FailedPrecondition, "el respaldo %s no tiene una ficha con firma válida de esta bóveda (respaldo anterior a la firma, ficha alterada o de otra bóveda): se puede ver y comparar, pero no se restaura; toma un respaldo nuevo", r.BackupId)
	}
	ch := assist.RestoreChange{Backup: text, BackupMasked: e.Masked, Management: r.ManagementInterface, BackupSerial: e.Serial, BackupTruncated: e.Truncated,
		MaxLines: int(r.MaxLines), Partial: r.AllowPartial}
	var rp assist.RestorePlan
	var buildErr error
	var fn assist.Function
	id, plan, err := s.planWith(ctx, r.Target, r.AcceptedHostKeyFingerprints, assist.RestoreDiffPre(), assist.RestoreEgressPre, &fn, nil, r.WriteMemory,
		fmt.Sprintf("respaldo=%s parcial=%t", r.BackupId, r.AllowPartial), nil,
		func(label string, outs map[string]string) (assist.DevicePlan, error) {
			rp, buildErr = assist.RestoreDiffPlan(label, ch, outs)
			fn = rp.Fn
			return rp.Device, buildErr
		})
	if err != nil {
		if buildErr != nil && len(rp.Refused) > 0 && errors.Is(buildErr, assist.ErrRestoreRefused) {
			s.d.Audit("assist.plan.refused", r.Target.Address, fmt.Sprintf("función=%s respaldo=%s rechazados=%d", assist.RestoreDiff, r.BackupId, len(rp.Refused)))
			return &v1.PlanRestoreResponse{Refused: refusalsToProto(rp.Refused), Reason: buildErr.Error()}, nil
		}
		return nil, err
	}
	return &v1.PlanRestoreResponse{PlanId: id, Plan: planToProto(assist.Redact(plan, fn)), Refused: refusalsToProto(rp.Refused)}, nil
}

func refusalsToProto(rs []assist.Refusal) []*v1.RestoreRefusal {
	var out []*v1.RestoreRefusal
	for _, r := range rs {
		out = append(out, &v1.RestoreRefusal{Path: r.Path, Line: r.Line, Why: r.Why})
	}
	return out
}
