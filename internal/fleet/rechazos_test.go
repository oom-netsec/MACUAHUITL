package fleet

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestRechazosSeAgrupanPorComando(t *testing.T) {
	w := &ws{}
	for _, d := range []string{"CE2", "CE1", "CE3"} {
		w.reject(d, "show mac address-table", "2026-01-01 10:00Z")
	}
	w.reject("R9", "show ip dhcp snooping binding", "2026-01-01 10:00Z")
	list, txs := w.out()
	if len(list) != 2 || len(txs) != 2 {
		t.Fatalf("%q", list)
	}
	if want := "show mac address-table: los equipos lo rechazaron (3): CE1, CE2, CE3; se ignora"; list[0] != want && list[1] != want {
		t.Errorf("%q", list)
	}
	if want := "show mac address-table: rejected by 3 devices: CE1, CE2, CE3; ignored"; txs[0].In(i18n.En) != want && txs[1].In(i18n.En) != want {
		t.Errorf("%q", txs)
	}
	// un equipo solo conserva el formato de siempre
	for _, s := range list {
		if strings.Contains(s, "R9") && !strings.HasPrefix(s, "R9 · show ip dhcp snooping binding: el equipo rechazó") {
			t.Errorf("%q", s)
		}
	}
}

func TestRechazosCortanLaListaLarga(t *testing.T) {
	w := &ws{}
	for i := 0; i < 12; i++ {
		w.reject("R"+string(rune('A'+i)), "show x", "t")
	}
	list, _ := w.out()
	if len(list) != 1 || !strings.Contains(list[0], "(12)") || !strings.HasSuffix(list[0], "RJ, …; se ignora") {
		t.Errorf("%q", list)
	}
}
