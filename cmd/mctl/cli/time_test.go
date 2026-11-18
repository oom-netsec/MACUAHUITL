package cli

import (
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"strings"
	"testing"
	"time"
)

func TestTimeLocalConZona(t *testing.T) {
	old := i18n.DisplayZone
	i18n.DisplayZone = time.FixedZone("CST", -6*3600)
	defer func() { i18n.DisplayZone = old }()
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

func TestStateLineHoraConZona(t *testing.T) {
	old := i18n.DisplayZone
	i18n.DisplayZone = time.FixedZone("CST", -6*3600)
	defer func() { i18n.DisplayZone = old }()
	got := StateLine(&v1.AssistRunState{RunId: "r", State: "ok", StartedUnix: time.Date(2026, 11, 18, 4, 13, 9, 0, time.UTC).Unix()})
	if !strings.Contains(got, "2026-11-17 22:13:09 CST") {
		t.Errorf("%q", got)
	}
}
