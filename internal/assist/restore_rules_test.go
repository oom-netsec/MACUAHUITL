package assist

import (
	"strings"
	"testing"
)

// El detector de respaldo enmascarado acepta el marcador nuevo y el viejo (datos ya guardados).
func TestMaskReAceptaAmbosMarcadores(t *testing.T) {
	for _, m := range []string{"<hidden>", "<oculto>", "<masked>"} {
		if !maskRe.MatchString("snmp-server community " + m) {
			t.Errorf("maskRe no reconoce %s", m)
		}
	}
	if got := redact("enable secret 5 abc"); !strings.HasSuffix(got, "<hidden>") {
		t.Errorf("redact: %q", got)
	}
}
