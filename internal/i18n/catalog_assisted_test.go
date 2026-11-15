package i18n

import (
	"strings"
	"testing"
)

// El aviso de «solo se mostró el plan» nombra la bandera canónica --assisted en los dos idiomas (--asistido es alias).
func TestPlanSoloNombraAssisted(t *testing.T) {
	for _, k := range []string{"mctl.ports.plan_only", "mctl.snippet.plan_only", "mctl.restore.plan_only"} {
		for _, loc := range []string{Es, En} {
			if got := Msg(loc, k, nil); !strings.Contains(got, "--assisted") || strings.Contains(got, "--asistido") {
				t.Errorf("%s %s: %q", k, loc, got)
			}
		}
	}
}
