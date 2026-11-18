package i18n

import (
	"testing"
	"time"
)

// mx fija la zona local de la prueba, igual en Linux y Windows.
func mx(t *testing.T) {
	t.Helper()
	old := DisplayZone
	DisplayZone = time.FixedZone("CST", -6*3600)
	t.Cleanup(func() { DisplayZone = old })
}

func TestHoraLocalConZona(t *testing.T) {
	mx(t)
	u := time.Date(2026, 11, 18, 4, 13, 9, 7e6, time.UTC)
	for layout, want := range map[string]string{
		LocalMin: "2026-11-17 22:13 CST", LocalSec: "2026-11-17 22:13:09 CST", LocalMs: "2026-11-17 22:13:09.007 CST",
	} {
		if got := FmtLocal(u, layout); got != want {
			t.Errorf("%s: %q, quería %q", layout, got, want)
		}
	}
	if got := FmtLocal(time.Time{}, LocalMin); got != "-" {
		t.Errorf("hora cero: %q", got)
	}
	DisplayZone = time.FixedZone("Central Standard Time", -6*3600)
	if got := FmtLocal(u, LocalMin); got != "2026-11-17 22:13 -06:00" {
		t.Errorf("zona larga: %q", got)
	}
}

func TestHoraUnixCeroEsGuion(t *testing.T) {
	if got := FmtLocal(time.Unix(0, 0), LocalMin); got != "-" {
		t.Errorf("epoch 0: %q", got)
	}
}
