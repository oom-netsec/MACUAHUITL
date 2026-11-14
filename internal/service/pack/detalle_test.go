package pack

import (
	"errors"
	"strings"
	"testing"

	dom "github.com/oom-netsec/MACUAHUITL/internal/pack"
)

func TestInstallDetailAvisaDelFsync(t *testing.T) {
	p := &dom.Pack{Manifest: dom.Manifest{ID: "oom/x", Version: "1.0.0"}}
	if d := installDetail(p, "abc", &dom.Result{Pack: p}); strings.Contains(d, "fsync_warning") {
		t.Fatal(d)
	}
	d := installDetail(p, "abc", &dom.Result{Pack: p, SyncWarning: errors.New("disk")})
	if !strings.HasSuffix(d, ` fsync_warning="disk"`) {
		t.Fatal(d)
	}
}
