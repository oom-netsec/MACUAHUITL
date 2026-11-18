package scripts

import (
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestScriptsHoraLocalConZona(t *testing.T) {
	old := i18n.DisplayZone
	i18n.DisplayZone = time.FixedZone("CST", -6*3600)
	defer func() { i18n.DisplayZone = old }()
	if got := ts(time.Date(2026, 11, 18, 4, 13, 0, 0, time.UTC).UnixMilli()); got != "2026-11-17 22:13 CST" {
		t.Errorf("%q", got)
	}
}
