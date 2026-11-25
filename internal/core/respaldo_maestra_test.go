package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Exportar el respaldo pide la maestra actual: sin ella o errada no se escribe nada y el intento queda auditado.
func TestExportBackupPideLaMaestra(t *testing.T) {
	h, _ := bovedaConRespaldo(t, nil)
	ruta := filepath.Join(t.TempDir(), "nuevo.mcvault")
	for nombre, m := range map[string][]byte{"sin maestra": nil, "errada": []byte("no-es-la-maestra")} {
		_, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: ruta, Passphrase: []byte(fraseResp), Confirm: true, MasterPassword: m})
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: %v", nombre, err)
		}
		if _, err := os.Stat(ruta); err == nil {
			t.Fatalf("%s: escribió el respaldo", nombre)
		}
	}
	if !h.core.vault.Unlocked() {
		t.Fatal("comprobar la maestra cerró la bóveda")
	}
	if a := h.auditText(t); strings.Count(a, `"action":"vault.respaldo.exportar_fallido"`) != 2 || strings.Contains(a, "no-es-la-maestra") {
		t.Fatalf("auditoría: %s", a)
	}
	m := []byte("maestra")
	if _, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: ruta, Passphrase: []byte(fraseResp), Confirm: true, MasterPassword: m}); err != nil {
		t.Fatal(err)
	}
}

// Con la bóveda cerrada no se compara la maestra: correcta y errada dan el mismo error y no queda ningún fallo auditado.
func TestExportBackupCerradaNoComparaLaMaestra(t *testing.T) {
	h := newHarness(t, nil)
	h.vault.Create(ctx(t), &v1.CreateRequest{MasterPassword: []byte("maestra-larga-123")})
	h.vault.Lock(ctx(t), &v1.LockRequest{})
	var msgs []string
	for _, m := range []string{"maestra-larga-123", "otra-maestra-1"} {
		_, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: filepath.Join(t.TempDir(), "r.mcvault"), Passphrase: []byte(fraseResp), Confirm: true, MasterPassword: []byte(m)})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("%q: %v", m, err)
		}
		msgs = append(msgs, err.Error())
	}
	if msgs[0] != msgs[1] {
		t.Fatalf("errores distintos:\n%s\n%s", msgs[0], msgs[1])
	}
	if a := h.auditText(t); strings.Contains(a, "exportar_fallido") || strings.Contains(a, "unlock_failed") {
		t.Fatalf("auditoría: %s", a)
	}
}

// Maestra vacía y errada: el mismo error (no se distingue una de otra).
func TestExportBackupMaestraVaciaYErradaIguales(t *testing.T) {
	h, _ := bovedaConRespaldo(t, nil)
	var msgs []string
	for _, m := range [][]byte{nil, []byte("no-es-la-maestra")} {
		_, err := h.vault.ExportBackup(ctx(t), &v1.ExportBackupRequest{Path: filepath.Join(t.TempDir(), "r.mcvault"), Passphrase: []byte(fraseResp), Confirm: true, MasterPassword: m})
		msgs = append(msgs, status.Convert(err).Message())
	}
	if msgs[0] != msgs[1] {
		t.Fatalf("errores distintos: %q %q", msgs[0], msgs[1])
	}
}

// Cambiar la maestra con la actual errada queda auditado (como un desbloqueo fallido).
func TestChangeMasterErradaQuedaAuditado(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	_, err := h.vault.ChangeMasterPassword(ctx(t), &v1.ChangeMasterPasswordRequest{CurrentMasterPassword: []byte("mala"), NewMasterPassword: []byte("nueva-maestra-1")})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatal(err)
	}
	if a := h.auditText(t); !strings.Contains(a, `"action":"vault.change_master_failed"`) || strings.Contains(a, "nueva-maestra-1") {
		t.Fatalf("auditoría: %s", a)
	}
}
