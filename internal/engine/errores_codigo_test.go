package engine

import (
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestErroresDelPlanificadorConCodigo(t *testing.T) {
	now := time.Now()
	s := NewScheduler(nil, nil, func() time.Time { return now })
	err := s.Arm("j", Schedule{}, now.Add(-time.Second), nil, nil)
	if err == nil || err.Error() != "engine: el fin del trabajo ya pasó" || i18n.English(err) != "engine: the job's end time has already passed" {
		t.Errorf("fin: %v / %q", err, i18n.English(err))
	}
	s.jobs["j"] = &armed{}
	err = s.Arm("j", Schedule{}, now.Add(time.Hour), nil, nil)
	if err == nil || err.Error() != "engine: j ya está armado" || i18n.English(err) != "engine: j is already armed" {
		t.Errorf("dup: %v / %q", err, i18n.English(err))
	}
}
