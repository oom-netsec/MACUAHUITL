package change

import (
	"context"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

type estadoDeps struct {
	*servicetest.Deps
	state string
}

func (d estadoDeps) Job(context.Context, string) (service.JobInfo, error) {
	return service.JobInfo{State: d.state}, nil
}

// Un PRE sin POST está «en uso»; con POST ya no (46c).
func TestPinnedPreSinPost(t *testing.T) {
	s := &changeSvc{d: estadoDeps{servicetest.New(t), "completed"}, changes: map[string]*changeRec{"c1": {id: "c1"}}}
	if p := s.pinned(); len(p) != 0 {
		t.Fatalf("sin PRE: %v", p)
	}
	s.changes["c1"].jobs[v1.ChangePhase_CHANGE_PHASE_PRE] = "pre1"
	if p := s.pinned(); len(p) != 1 || p[0] != (service.PinnedJob{ID: "pre1", Reason: "change_pre"}) {
		t.Fatalf("pinned = %v", p)
	}
	s.changes["c1"].jobs[v1.ChangePhase_CHANGE_PHASE_POST] = "post1"
	if p := s.pinned(); len(p) != 0 {
		t.Fatalf("con POST: %v", p)
	}
}

// Un PRE que nunca se armó (ArmJob falló en CaptureChange) no tiene evidencia: no queda fijado.
func TestPinnedPreNuncaArmadoNoSeFija(t *testing.T) {
	s := &changeSvc{d: estadoDeps{servicetest.New(t), "created"}, changes: map[string]*changeRec{"c1": {id: "c1"}}}
	s.changes["c1"].jobs[v1.ChangePhase_CHANGE_PHASE_PRE] = "pre1"
	if p := s.pinned(); len(p) != 0 {
		t.Fatalf("pinned = %v", p)
	}
}
