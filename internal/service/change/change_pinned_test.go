package change

import (
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
)

// Un PRE sin POST está «en uso»; con POST ya no (46c).
func TestPinnedPreSinPost(t *testing.T) {
	s := &changeSvc{changes: map[string]*changeRec{"c1": {id: "c1"}}}
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
