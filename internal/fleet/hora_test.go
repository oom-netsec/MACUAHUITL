package fleet

import (
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"strings"
	"testing"
	"time"
)

func TestStampEnHoraLocal(t *testing.T) {
	old := i18n.DisplayZone
	i18n.DisplayZone = time.FixedZone("CST", -6*3600)
	defer func() { i18n.DisplayZone = old }()
	f := &Fleet{Now: time.Date(2026, 11, 18, 4, 20, 0, 0, time.UTC)}
	if got := f.Stamp(time.Date(2026, 11, 18, 4, 13, 0, 0, time.UTC)); !strings.HasPrefix(got, "2026-11-17 22:13 CST (") {
		t.Errorf("%q", got)
	}
}
