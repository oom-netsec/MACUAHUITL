package cli

import (
	"testing"
	"time"
)

func TestTimeLocalConZona(t *testing.T) {
	old := time.Local
	time.Local = time.FixedZone("CST", -6*3600)
	defer func() { time.Local = old }()
	u := time.Date(2026, 11, 18, 4, 13, 0, 0, time.UTC)
	if got := Time(u.UnixMilli()); got != "2026-11-17 22:13 CST" {
		t.Errorf("Time: %q", got)
	}
	if got := TimeSecOf(u); got != "2026-11-17 22:13:00 CST" {
		t.Errorf("TimeSecOf: %q", got)
	}
	if got := Time(0); got != "-" {
		t.Errorf("0 no es fecha: %q", got)
	}
}
