package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func labDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs("../analyze/testdata/lab_20261104-100000")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnalysisByFolderAudited(t *testing.T) {
	h := newHarness(t, nil)
	ac := v1.NewAnalysisServiceClient(h.conn)
	r, err := ac.AnalyzeJob(ctx(t), &v1.AnalyzeJobRequest{Job: labDir(t), Round: 3, Device: "SW1"})
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct{ Rule string }
	}
	if err := json.Unmarshal([]byte(r.Report.Json), &rep); err != nil || len(rep.Findings) == 0 {
		t.Fatalf("report %v: %s", err, r.Report.Json)
	}
	if !strings.Contains(r.Report.Text, "cpu-alta") && !strings.Contains(r.Report.Text, "CPU alta") {
		t.Fatalf("text: %s", r.Report.Text)
	}
	d, err := ac.DiffRounds(ctx(t), &v1.DiffRoundsRequest{Job: labDir(t), From: 1, To: 2})
	if err != nil || !strings.Contains(d.Report.Json, `"delta":1500`) {
		t.Fatalf("diff %v: %s", err, d.GetReport().GetJson())
	}
	txt := h.auditText(t)
	for _, a := range []string{`"action":"analysis.run"`, `"action":"analysis.diff"`} {
		if !strings.Contains(txt, a) {
			t.Errorf("not audited: %s", a)
		}
	}
}

func TestAnalysisRejectsBadInput(t *testing.T) {
	h := newHarness(t, nil)
	ac := v1.NewAnalysisServiceClient(h.conn)
	if _, err := ac.AnalyzeJob(ctx(t), &v1.AnalyzeJobRequest{Job: "no-existe"}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown job: %v", err)
	}
	if _, err := ac.AnalyzeJob(ctx(t), &v1.AnalyzeJobRequest{Job: t.TempDir()}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("empty folder: %v", err)
	}
	if _, err := ac.DiffRounds(ctx(t), &v1.DiffRoundsRequest{Job: labDir(t), From: 1, To: 9}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("missing round: %v", err)
	}
	if _, err := ac.Timeline(ctx(t), &v1.TimelineRequest{Job: labDir(t), PcapPath: "rel.pcap"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("relative pcap: %v", err)
	}
}

func TestTimelineCorrelatesSyslog(t *testing.T) {
	h := newHarness(t, nil)
	dir := filepath.Join(h.out, "syslog")
	os.MkdirAll(dir, 0o700)
	// El receptor nombra el archivo con la hora local del núcleo.
	name := "syslog_" + time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC).In(time.Local).Format("20060102-150405") + ".log"
	os.WriteFile(filepath.Join(dir, name), []byte(
		"2026-11-04T10:09:19Z 10.0.0.2:514 <189>%BGP-5-ADJCHANGE: neighbor 10.0.13.1 Down\n"+
			"2026-11-04T23:00:00Z 10.0.0.2:514 <189>muy lejos del trabajo\n"), 0o600)
	ac := v1.NewAnalysisServiceClient(h.conn)
	r, err := ac.Timeline(ctx(t), &v1.TimelineRequest{Job: labDir(t), Around: timestamppb.New(time.Date(2026, 11, 4, 10, 9, 18, 0, time.UTC)), WindowSeconds: 30, Device: "RTR2"})
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Events []struct{ Source, Device, Text string }
	}
	json.Unmarshal([]byte(r.Report.Json), &rep)
	var syslog, logs int
	for _, e := range rep.Events {
		if e.Source == "syslog" && e.Device == "RTR2_10.0.0.2" {
			syslog++
		}
		if e.Source == "log-equipo" {
			logs++
		}
		if strings.HasPrefix(e.Device, "SW1") {
			t.Errorf("device filter leaked %+v", e)
		}
	}
	if syslog != 1 || logs == 0 {
		t.Fatalf("syslog=%d logs=%d: %s", syslog, logs, r.Report.Text)
	}
	// Sin ventana: el syslog lejano al trabajo queda fuera.
	r, _ = ac.Timeline(ctx(t), &v1.TimelineRequest{Job: labDir(t)})
	if strings.Contains(r.Report.Json, "muy lejos") || !strings.Contains(r.Report.Json, "ADJCHANGE") {
		t.Fatalf("margin: %s", r.Report.Text)
	}
	if !strings.Contains(h.auditText(t), `"action":"analysis.timeline"`) {
		t.Fatal("timeline not audited")
	}
}

// Integración: lo que Patrol escribe de verdad (simulador) se puede analizar por ID de trabajo.
func TestAnalysisOfRealJobByID(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.arm(t, cred)
	ac := v1.NewAnalysisServiceClient(h.conn)
	h.waitJob(t, job, "closed")
	r, err := ac.AnalyzeJob(ctx(t), &v1.AnalyzeJobRequest{Job: job})
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Devices []string
		Rounds  []int
	}
	json.Unmarshal([]byte(r.Report.Json), &rep)
	if len(rep.Devices) != 1 || len(rep.Rounds) != 2 {
		t.Fatalf("report: %s", r.Report.Json)
	}
	if _, err := ac.DiffRounds(ctx(t), &v1.DiffRoundsRequest{Job: job, From: 1, To: 2}); err != nil {
		t.Fatal(err)
	}
}
