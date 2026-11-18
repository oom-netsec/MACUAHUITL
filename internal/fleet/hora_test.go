package fleet

import (
	"strings"
	"testing"
	"time"
)

func TestStampEnHoraLocal(t *testing.T) {
	old := time.Local
	time.Local = time.FixedZone("CST", -6*3600)
	defer func() { time.Local = old }()
	f := &Fleet{Now: time.Date(2026, 11, 18, 4, 20, 0, 0, time.UTC)}
	if got := f.Stamp(time.Date(2026, 11, 18, 4, 13, 0, 0, time.UTC)); !strings.HasPrefix(got, "2026-11-17 22:13 CST (") {
		t.Errorf("%q", got)
	}
}
