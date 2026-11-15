package backup

import (
	"context"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/backup"
)

// Visto en CML (2026-11-14): un respaldo tomado con --secrets contra uno enmascarado (el de --now) imprimía los hashes
// del primero (tipo 5/7, que se rompen) y marcaba una diferencia falsa solo por el enmascarado. Los dos lados se
// enmascaran para mostrar; un secreto que de verdad cambió sale como «secret changed», sin el valor.
func TestDiffNoMuestraSecretos(t *testing.T) {
	s, _, _, _ := nuevo(t, "completed")
	ctx := context.Background()
	save := func(h int, masked bool, text string) string {
		t.Helper()
		e, _, err := s.store().Save(backup.Entry{Device: dev, Kind: backup.Running, At: time.Date(2026, 11, 6, h, 0, 0, 0, time.UTC), Masked: masked}, text)
		if err != nil {
			t.Fatal(err)
		}
		return e.ID
	}
	conSecretos := save(8, false, "hostname SW1\nenable secret 5 $1$abcd$Hash5Viejo\nusername cisco privilege 15 secret 5 $1$efgh$HashUsr\ninterface Gi1/0/1\n description PC-01\n")
	enmascarado := save(9, true, "hostname SW1\nenable secret 5 <MASKED:enable-secret>\nusername cisco privilege 15 secret 5 <MASKED:user-secret>\ninterface Gi1/0/1\n description PC-01\n")
	otraClave := save(10, false, "hostname SW1\nenable secret 5 $1$zzzz$Hash5Nuevo\nusername cisco privilege 15 secret 5 $1$efgh$HashUsr\ninterface Gi1/0/1\n description PC-01\n")

	r, err := s.DiffBackups(ctx, &v1.DiffBackupsRequest{From: conSecretos, To: enmascarado})
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"Hash5Viejo", "HashUsr", "$1$"} {
		if strings.Contains(r.Report.Text, leak) || strings.Contains(r.Report.Json, leak) {
			t.Errorf("el diff muestra %q:\n%s", leak, r.Report.Text)
		}
	}
	if strings.Contains(r.Report.Text, "enable secret") {
		t.Errorf("diferencia falsa por el enmascarado:\n%s", r.Report.Text)
	}

	r, err = s.DiffBackups(ctx, &v1.DiffBackupsRequest{From: conSecretos, To: otraClave})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Report.Text, "Hash5") || !strings.Contains(r.Report.Text, "~ enable secret 5 <MASKED:enable-secret> (la clave cambió") || strings.Contains(r.Report.Text, "username cisco") {
		t.Errorf("con dos respaldos con secretos debe decir que la clave cambió, sin el valor, y no listar la que no cambió:\n%s", r.Report.Text)
	}
}
