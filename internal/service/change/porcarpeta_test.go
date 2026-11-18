package change

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// salidas arma la carpeta de un trabajo ya quitado del historial: dos rondas de running-config de SW1 (el servicetest no conoce el id).
func salidas(t *testing.T, cfgs ...string) string {
	t.Helper()
	dir := t.TempDir()
	d := filepath.Join(dir, "SW1_192.0.2.1")
	os.MkdirAll(d, 0o755)
	for i, c := range cfgs {
		h := string(rune('0'+(10+i)/10)) + string(rune('0'+(10+i)%10))
		txt := "===== 2026-11-06T" + h + ":00:00Z · show running-config =====\n" + c
		os.WriteFile(filepath.Join(d, "r00"+string(rune('1'+i))+"_20261106-"+h+"0000.txt"), []byte(txt), 0o600)
	}
	os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"masked":true}`), 0o600)
	return dir
}

func TestReporteDeCambioPorCarpetasTrasQuitar(t *testing.T) {
	pre, post := salidas(t, "hostname SW1\n"), salidas(t, "hostname SW1\nvlan 10\n")
	s := &changeSvc{d: servicetest.New(t), changes: map[string]*changeRec{}}
	if r, err := s.GetChangeReport(context.Background(), &v1.GetChangeReportRequest{PreDir: pre, PostDir: post}); err != nil || r.Report == nil {
		t.Errorf("GetChangeReport: %v", err)
	}
}
