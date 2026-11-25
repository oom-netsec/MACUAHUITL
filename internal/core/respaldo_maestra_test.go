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
