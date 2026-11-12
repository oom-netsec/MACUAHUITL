package core

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Con en, la deriva y la limpieza salen en inglés (informe, motivos, marcas en la salida y errores) con sus claves.
func TestDerivaYLimpiezaIdioma(t *testing.T) {
	h := newHarness(t, nil)
	fx := newFlotaFx(t)
	for _, lang := range []string{"", "en"} {
		sub := map[string]flotaRec{}
		for n, r := range flotaCases(t, h, lang, fx) {
			if strings.HasPrefix(n, "drift.") || strings.HasPrefix(n, "cleaner.") {
				sub[n] = r
			}
		}
		checkKeys(t, lang, sub)
		if lang != "en" {
			if !strings.Contains(sub["cleaner.sucia"].Extra, "! HUERFANA: route-map RM-FALTA") {
				t.Errorf("la salida en español cambió")
			}
			continue
		}
		c := sub["cleaner.sucia"]
		if !strings.Contains(c.Extra, "! ORPHAN: route-map RM-FALTA does not exist") || strings.Contains(c.Extra, "HUERFANA") {
			t.Errorf("salida en inglés:\n%s", c.Extra)
		}
		if !strings.Contains(c.Text, "ORPHANS") || strings.Contains(c.Json, "no existe") || !strings.Contains(c.Json, "does not exist") {
			t.Errorf("informe en inglés:\n%s", c.Text)
		}
		d := sub["drift.0"]
		if !strings.Contains(d.Text, "devices with drift") || !strings.Contains(d.Text, "no two rounds with running-config") && !strings.Contains(d.Json, "no two rounds with running-config") {
			t.Errorf("deriva en inglés:\n%s\n%s", d.Text, d.Json)
		}
		if !strings.Contains(d.Text, "(round 2 against 1)") && !strings.Contains(d.Text, "round 2 against 1") {
			t.Errorf("deriva en inglés:\n%s", d.Text)
		}
	}
	dc := v1.NewDriftServiceClient(h.conn)
	if _, err := dc.Drift(con(t, "en"), &v1.DriftRequest{Job: fx.drift, Round: 1}); status.Code(err) != codes.FailedPrecondition || !strings.HasPrefix(status.Convert(err).Message(), "no device has two rounds") {
		t.Errorf("drift err en: %v", err)
	}
	if _, err := v1.NewCleanerServiceClient(h.conn).Clean(con(t, "en"), &v1.CleanRequest{}); status.Convert(err).Message() != "the configuration is missing" {
		t.Errorf("cleaner err en: %v", err)
	}
}
