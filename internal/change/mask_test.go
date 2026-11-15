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
