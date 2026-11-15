package cli

import (
	"strings"
	"testing"
)

// El aviso de reversa guardada nombra el subcomando del tipo de la ejecución: un snippet abortado no manda a
// «mctl ports rollback» (funcionaba igual, pero confunde).
func TestRollbackAreaPorTipo(t *testing.T) {
	for kind, want := range map[string]string{"ports": "ports", "snippet-vlan": "snippet", "snippet-snmp-community": "snippet",
		"restore-diff": "restore", "": "ports", "otra-cosa": "ports"} {
		if got := rollbackArea(kind); got != want {
			t.Errorf("rollbackArea(%q) = %q, quiero %q", kind, got, want)
		}
	}
	for _, loc := range []string{"es", "en"} {
		SetLang(loc)
		if got := T("mctl.run.warn_pending", "devices", "SW1", "run", "abc", "area", "snippet"); !strings.Contains(got, "mctl snippet rollback abc") {
			t.Errorf("%s: %q", loc, got)
		}
	}
	SetLang("")
}

// El uso y las banderas de «snippet rollback» y «restore rollback» nombran su propio subcomando, no «ports rollback».
func TestRollbackUsoNombraSuArea(t *testing.T) {
	for _, area := range []string{"ports", "snippet", "restore"} {
		var out strings.Builder
		err := RollbackIn(area)(&Env{Out: &out}, nil)
		if err == nil || !strings.Contains(err.Error(), "mctl "+area+" rollback") || (area != "ports" && strings.Contains(err.Error(), "ports rollback")) {
			t.Errorf("%s: %v", area, err)
		}
	}
}
