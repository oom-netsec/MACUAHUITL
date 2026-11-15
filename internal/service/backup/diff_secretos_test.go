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
	for _, side := range []string{`"before"`, `"after"`} { // los textos para el visor de la UI, ya enmascarados
		if !strings.Contains(r.Report.Json, side) {
			t.Errorf("falta %s en el JSON", side)
		}
	}
	if strings.Contains(r.Report.Text, "enable secret") {
		t.Errorf("diferencia falsa por el enmascarado:\n%s", r.Report.Text)
	}

	r, err = s.DiffBackups(ctx, &v1.DiffBackupsRequest{From: conSecretos, To: otraClave})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(r.Report.Text, "Hash5") || !strings.Contains(r.Report.Text, "~ enable secret 5 <MASKED:enable-secret> (cambió un valor enmascarado") || strings.Contains(r.Report.Text, "username cisco") {
		t.Errorf("con dos respaldos con secretos debe decir que la clave cambió, sin el valor, y no listar la que no cambió:\n%s", r.Report.Text)
	}
}

// Aviso de evidencia sin enmascarar: sale si alguno de los dos respaldos se tomó con --secrets, y no si los dos se enmascararon.
func TestDiffAvisaSinEnmascarar(t *testing.T) {
	s, _, _, _ := nuevo(t, "completed")
	save := func(h int, masked bool) string {
		e, _, err := s.store().Save(backup.Entry{Device: dev, Kind: backup.Running, At: time.Date(2026, 11, 6, h, 0, 0, 0, time.UTC), Masked: masked}, "hostname SW"+string(rune('A'+h))+"\n")
		if err != nil {
			t.Fatal(err)
		}
		return e.ID
	}
	m1, m2, u := save(8, true), save(9, true), save(10, false)
	for _, c := range []struct {
		a, b string
		want bool
	}{{m1, m2, false}, {m1, u, true}, {u, m2, true}} {
		r, err := s.DiffBackups(context.Background(), &v1.DiffBackupsRequest{From: c.a, To: c.b})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(r.Report.Text, "sin enmascarar: puede traer secretos"); got != c.want || strings.Contains(r.Report.Json, `"unmasked":true`) != c.want {
			t.Errorf("aviso=%v, quería %v:\n%s", got, c.want, r.Report.Text)
		}
	}
}
