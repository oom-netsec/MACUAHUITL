package change

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

// B2: el diff de configuración enmascara siempre, también con evidencia recogida sin máscara (--secrets).
func TestConfigDiffEnmascaraLosSecretos(t *testing.T) {
	a := Snapshot{Have: map[string]bool{"config": true}, Config: iosconf.Parse("hostname R1\nradius server R\n key 7 OLDRADK1\n")}
	b := Snapshot{Have: map[string]bool{"config": true}, Config: iosconf.Parse(
		"hostname R1\nradius server R\n key 7 NEWRADK1\nusername bob secret 0 NEWUSR1\nsnmp-server community NEWCOM1 RO\n")}
	_, diff, _ := compareDevice(a, b)
	all := strings.Join(diff, "\n")
	for _, leak := range []string{"OLDRADK1", "NEWRADK1", "NEWUSR1", "NEWCOM1"} {
		if strings.Contains(all, leak) {
			t.Errorf("el diff muestra %s:\n%s", leak, all)
		}
	}
	if len(diff) != 4 || !strings.Contains(all, "radius server R > key 7 <MASKED:") {
		t.Errorf("el diff cambió de forma:\n%s", all)
	}
}

// M4: con la plataforma real (ASA) el host SNMP «host IFNAME IP» se ve y la comunidad no.
func TestConfigDiffUsaLaPlataformaDelEquipo(t *testing.T) {
	a := Snapshot{Platform: "asa", Have: map[string]bool{"config": true}, Config: iosconf.Parse("hostname fw\n")}
	b := Snapshot{Platform: "asa", Have: map[string]bool{"config": true}, Config: iosconf.Parse(
		"hostname fw\nsnmp-server host inside 10.0.0.1\nsnmp-server host inside 10.0.0.2 community ZQCOM1 version 2c\n")}
	_, diff, _ := compareDevice(a, b)
	all := strings.Join(diff, "\n")
	if !strings.Contains(all, "host inside 10.0.0.1") || !strings.Contains(all, "10.0.0.2") || strings.Contains(all, "ZQCOM1") {
		t.Errorf("%s", all)
	}
}
