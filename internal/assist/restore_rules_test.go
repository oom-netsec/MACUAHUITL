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

// Lo que crean snmp-trap-host y netflow-export no se restaura con restore-diff: se rechaza con su motivo, no con el genérico.
func TestForbiddenCubreTrapsYNetflow(t *testing.T) {
	for _, l := range []string{
		"snmp-server host 10.1.1.5 version 2c Zx9-Secreta.Comm udp-port 162", "no snmp-server host 10.1.1.5 version 2c abcd",
		"snmp-server enable traps snmp linkdown linkup coldstart", "no snmp-server enable traps config", "snmp-server enable traps",
		"flow record MX-REC", "no flow exporter MX-EXP", "flow monitor MX-MON", "ip flow monitor MX-MON input", "no ip flow monitor MX-MON input",
	} {
		if forbiddenWhy(tokens(l)).Empty() {
			t.Errorf("%q no tiene motivo propio en la lista de familias prohibidas", l)
		}
	}
	for _, l := range []string{"snmp-server location Lab", "ip flowx", "ip domain-name x"} {
		if got := forbiddenWhy(tokens(l)); !got.Empty() {
			t.Errorf("%q no debía caer en las nuevas: %v", l, got)
		}
	}
}
