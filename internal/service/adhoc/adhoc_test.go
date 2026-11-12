package adhoc

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

type jobDeps struct {
	*servicetest.Deps
	info service.JobInfo
}

func (d jobDeps) Job(string) (service.JobInfo, error) { return d.info, nil }

func TestResultadoFinalLiberaLosComandos(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"devices":[]}`), 0o600)
	s := &adhocSvc{d: jobDeps{servicetest.New(t), service.JobInfo{State: "completed", Dir: dir}}, cmds: map[string][]string{"j1": {"show clock"}}}
	r, err := s.AdhocResult(context.Background(), &v1.AdhocResultRequest{JobId: "j1"})
	if err != nil || !r.Done || r.Error != "" {
		t.Fatalf("%+v %v", r, err)
	}
	if len(s.cmds) != 0 {
		t.Errorf("cmds no se liberó: %v", s.cmds)
	}
}

func TestResultadoConFinishFallidoTerminaConError(t *testing.T) {
	s := &adhocSvc{d: jobDeps{servicetest.New(t), service.JobInfo{State: "completed", Dir: t.TempDir(), FinishErr: "disco lleno"}}, cmds: map[string][]string{"j1": {"show clock"}}}
	r, err := s.AdhocResult(context.Background(), &v1.AdhocResultRequest{JobId: "j1"})
	if err != nil || !r.Done || r.Error != "disco lleno" || r.Report != nil {
		t.Fatalf("%+v %v", r, err)
	}
	if len(s.cmds) != 0 {
		t.Errorf("cmds no se liberó: %v", s.cmds)
	}
	// Sin error de cierre, un manifest que aún no existe no es final.
	s.d = jobDeps{servicetest.New(t), service.JobInfo{State: "completed", Dir: t.TempDir()}}
	if r, _ = s.AdhocResult(context.Background(), &v1.AdhocResultRequest{JobId: "j1"}); r.Done {
		t.Errorf("sin manifest ni error no está listo: %+v", r)
	}
}
