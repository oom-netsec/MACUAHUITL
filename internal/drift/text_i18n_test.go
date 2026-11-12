package drift

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestInformeEnIngles(t *testing.T) {
	cs := []Change{{"+", "interface Gi1", " description x"}, {"-", "", "ntp server 1.1.1.1"}}
	r := Report{Dir: "d", Devices: []DeviceDrift{NewDevice("SW1", 1, 2, cs, []string{"ntp clock-period 1"}), NewDevice("SW2", 1, 2, nil, nil)}, Masked: true,
		Warnings: []string{"SW3: sin dos rondas con running-config (tiene [2])"}, WarningsTx: []i18n.Text{i18n.Tx("drift.warn.no_pair", "dev", "SW3", "have", "[2]")}}
	es := r.Text()
	for _, w := range []string{"AVISO: los cambios en secretos", "SW1: 2 cambios (1 agregadas, 1 quitadas), ronda 2 contra 1", "ignoradas por volátiles", "Aviso: SW3: sin dos rondas", "1 de 2 equipos con deriva"} {
		if !strings.Contains(es, w) {
			t.Errorf("falta %q en el español:\n%s", w, es)
		}
	}
	keys := i18n.Localize(&r, i18n.En)
	if len(keys) != 1 {
		t.Errorf("claves: %v", keys)
	}
	en := r.TextIn(i18n.En)
	for _, w := range []string{"WARNING: changes to secrets are not visible", "SW1: 2 changes (1 added, 1 removed), round 2 against 1", "ignored as volatile", "Warning: SW3: no two rounds", "1 of 2 devices with drift", "SW2: no drift"} {
		if !strings.Contains(en, w) {
			t.Errorf("falta %q en inglés:\n%s", w, en)
		}
	}
}
