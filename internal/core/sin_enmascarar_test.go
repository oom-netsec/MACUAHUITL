package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// jobSinManifestoCompleto arma una carpeta de trabajo con dos rondas de running-config y el masked dado.
func jobMasked(t *testing.T, masked string) string {
	t.Helper()
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "manifest.json"), []byte(`{"masked":`+masked+`,"devices":[]}`), 0o600)
	os.MkdirAll(filepath.Join(d, "sw1_10.0.0.1"), 0o700)
	for i, ts := range []string{"10:00:00", "10:10:00"} {
		body := "===== 2026-11-14T" + ts + "Z · show running-config =====\nhostname sw1\ninterface Gi0/" + string(rune('1'+i)) + "\n"
		os.WriteFile(filepath.Join(d, "sw1_10.0.0.1", "r00"+string(rune('1'+i))+"_20261114-100000.txt"), []byte(body), 0o600)
	}
	return d
}

// Aviso de evidencia sin enmascarar: aparece solo si el manifest dice masked:false.
func TestAvisoSinEnmascarar(t *testing.T) {
	h := newHarness(t, nil)
	const es, en = "esta evidencia se recogió sin enmascarar", "this evidence was collected without masking"
	for _, c := range []struct {
		masked string
		want   bool
	}{{"true", false}, {"false", true}} {
		dir := jobMasked(t, c.masked)
		texts := map[string]string{}
		dr, err := v1.NewDriftServiceClient(h.conn).Drift(ctx(t), &v1.DriftRequest{Job: dir, Round: 2})
		if err != nil {
			t.Fatal(err)
		}
		texts["drift"] = dr.Report.Text + dr.Report.Json
		cr, err := v1.NewChangeServiceClient(h.conn).GetChangeReport(ctx(t), &v1.GetChangeReportRequest{PreDir: dir, PostDir: dir})
		if err != nil {
			t.Fatal(err)
		}
		texts["change"] = cr.Report.Text + cr.Report.Json
		ar, err := v1.NewAnalysisServiceClient(h.conn).AnalyzeJob(ctx(t), &v1.AnalyzeJobRequest{Job: dir})
		if err != nil {
			t.Fatal(err)
		}
		texts["analysis"] = ar.Report.Text + ar.Report.Json
		for name, tx := range texts {
			if got := strings.Contains(tx, es) || strings.Contains(tx, en); got != c.want {
				t.Errorf("%s masked=%s: aviso=%v, quería %v\n%s", name, c.masked, got, c.want, tx)
			}
		}
	}
}
