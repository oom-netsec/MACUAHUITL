package change

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestStpPortNingunoYTextoEn(t *testing.T) {
	f := stpPort("VLAN0010", "", "Gi1/0/1")
	if f.Detail != "VLAN0010: puerto raíz ninguno → Gi1/0/1" || f.DetailTx.In(i18n.En) != "VLAN0010: root port none → Gi1/0/1" {
		t.Errorf("%q / %q", f.Detail, f.DetailTx.In(i18n.En))
	}
}

func TestInformeEnIngles(t *testing.T) {
	r := Compare(nil, nil)
	r.Devices = []Device{{Address: "1.1.1.1", Hostname: "A", Verdict: Review, Findings: []Finding{finding("config", Info, "config", "added", 1, "removed", 2)}}}
	i18n.Localize(&r, i18n.En)
	if got := r.TextIn(i18n.En); got != "A (1.1.1.1): REVIEW\n  info       config     running-config: 1 added, 2 removed\n"+r.Note+"\n" || r.Note[:10] != "Comparison" {
		t.Errorf("%q", got)
	}
	if es := (Report{}).Text(); es != "\n" {
		t.Errorf("es vacío: %q", es)
	}
}

func TestMasLineasDeConfig(t *testing.T) {
	more := i18n.Tx("change.diff.more", "n", 3)
	if more.In(i18n.Es) != "… 3 líneas más" || more.In(i18n.En) != "… 3 more lines" {
		t.Errorf("%q %q", more.In(i18n.Es), more.In(i18n.En))
	}
}

// Los escenarios de la regresión recorren todos los hallazgos del cambio.
func TestEscenariosCubrenTodosLosHallazgos(t *testing.T) {
	_, ptrs := regCases(t)
	used := map[string]bool{}
	for _, v := range ptrs {
		for k := range i18n.UsedKeys(v) {
			used[k] = true
		}
	}
	for _, k := range i18n.Codes() {
		if strings.HasPrefix(k, "change.detail.") && !used[k] {
			t.Errorf("ningún escenario de la regresión produce %s", k)
		}
	}
}
