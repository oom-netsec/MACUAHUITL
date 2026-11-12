package core

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Con en, los informes de cambios, actualización y cumplimiento salen en inglés con sus claves; con es, lo de siempre.
func TestCambiosActualizacionYCumplimientoIdioma(t *testing.T) {
	h := newHarness(t, nil)
	fx := newFlotaFx(t)
	for _, lang := range []string{"", "en"} {
		sub := map[string]flotaRec{}
		for n, r := range flotaCases(t, h, lang, fx) {
			if strings.HasPrefix(n, "change.") || strings.HasPrefix(n, "upgrade.") || strings.HasPrefix(n, "compliance.") {
				sub[n] = r
			}
		}
		if n := checkKeys(t, lang, sub); n < 20 {
			t.Errorf("con %q solo %d claves", lang, n)
		}
		if lang == "en" {
			for n, r := range sub {
				if m := españolFlota.FindString(strings.NewReplacer("versión", "", "captura", "").Replace(r.Text)); m != "" && !strings.Contains(n, "err") {
					t.Errorf("%s: español (%s) en el texto en inglés:\n%.600s", n, m, r.Text)
				}
			}
			if !strings.Contains(sub["change.report"].Text, "REGRESSION") || !strings.Contains(sub["compliance.debil.txt"].Text, "FAIL") {
				t.Errorf("texto en inglés: %.300s", sub["change.report"].Text)
			}
		}
	}
	cc := v1.NewChangeServiceClient(h.conn)
	_, err := cc.CheckUpgrade(con(t, "en"), &v1.CheckUpgradeRequest{Outputs: "SW1#show version\nCisco IOS XE Software, Version 17.9.4a\n", ImageFile: ""})
	if status.Code(err) != codes.InvalidArgument || status.Convert(err).Message() != "upgrade: the image name is missing" {
		t.Errorf("upgrade en: %v", err)
	}
	if _, err := cc.CheckCompliance(con(t, "en"), &v1.CheckComplianceRequest{Config: ""}); status.Convert(err).Message() != "compliance: the configuration is empty" {
		t.Errorf("compliance en: %v", err)
	}
	if _, err := cc.CheckCompliance(con(t, ""), &v1.CheckComplianceRequest{Config: ""}); status.Convert(err).Message() != "compliance: la configuración está vacía" {
		t.Errorf("compliance es: %v", err)
	}
}
