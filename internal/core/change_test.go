package core

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// waitPhase espera a que la captura termine y su manifest exista (el reporte lo exige).
func waitPhase(t *testing.T, ch v1.ChangeServiceClient, id string, post bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		l, err := ch.ListChanges(ctx(t), &v1.ListChangesRequest{})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range l.Changes {
			st := c.PreState
			if post {
				st = c.PostState
			}
			if c.ChangeId == id && st == "completed" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("la captura no terminó")
}

func TestChangePrePostEndToEnd(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	ch := v1.NewChangeServiceClient(h.conn)
	spec := &v1.JobSpec{Name: "cambio-1", Targets: []*v1.Target{h.target}, DefaultCredentialId: cred, OutputDir: h.out,
		Schedule: &v1.Schedule{IntervalSeconds: 60, Rounds: 5}} // el núcleo lo fuerza a una ronda
	cr, err := ch.CreateChange(ctx(t), &v1.CreateChangeRequest{Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ch.CaptureChange(ctx(t), &v1.CaptureChangeRequest{ChangeId: cr.ChangeId, Phase: v1.ChangePhase_CHANGE_PHASE_POST}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("post before pre: %v", err)
	}
	// Llave de host nueva: el armado falla pero el trabajo queda creado para revisarlo.
	pre, err := ch.CaptureChange(ctx(t), &v1.CaptureChangeRequest{ChangeId: cr.ChangeId, Phase: v1.ChangePhase_CHANGE_PHASE_PRE})
	if err != nil || pre.Armed || pre.JobId == "" || !strings.Contains(pre.Detail, "Login Test") {
		t.Fatalf("pre = %+v %v", pre, err)
	}
	if k := h.summary(t, pre.JobId).Kind; k != "change" {
		t.Fatalf("kind = %q, quería change", k)
	}
	fp := h.loginTest(t, pre.JobId)[0].HostKeyFingerprint
	pre, err = ch.CaptureChange(ctx(t), &v1.CaptureChangeRequest{ChangeId: cr.ChangeId, Phase: v1.ChangePhase_CHANGE_PHASE_PRE, AcceptedHostKeyFingerprints: []string{fp}})
	if err != nil || !pre.Armed {
		t.Fatalf("pre = %+v %v", pre, err)
	}
	waitPhase(t, ch, cr.ChangeId, false)
	if _, err := ch.GetChangeReport(ctx(t), &v1.GetChangeReportRequest{ChangeId: cr.ChangeId}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("report without post: %v", err)
	}
	post, err := ch.CaptureChange(ctx(t), &v1.CaptureChangeRequest{ChangeId: cr.ChangeId, Phase: v1.ChangePhase_CHANGE_PHASE_POST})
	if err != nil || !post.Armed {
		t.Fatalf("post = %+v %v", post, err)
	}
	waitPhase(t, ch, cr.ChangeId, true)
	var rep struct {
		Devices []struct {
			Address, Verdict string
		}
	}
	var r *v1.GetChangeReportResponse
	for i := 0; i < 100; i++ { // el manifest se escribe justo después de "completed"
		if r, err = ch.GetChangeReport(ctx(t), &v1.GetChangeReportRequest{ChangeId: cr.ChangeId}); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(r.Report.Json), &rep); err != nil || len(rep.Devices) != 1 || rep.Devices[0].Verdict != "ok" {
		t.Fatalf("report = %s (%v)\n%s", r.Report.Json, err, r.Report.Text)
	}
	if !strings.Contains(r.Report.Text, "SIN CAMBIOS INESPERADOS") {
		t.Fatalf("text = %s", r.Report.Text)
	}
	l, _ := h.patrol.ListJobs(ctx(t), &v1.ListJobsRequest{})
	names := map[string]bool{}
	for _, j := range l.Jobs {
		names[j.Name] = true
	}
	if !names["cambio-1-pre"] || !names["cambio-1-post"] {
		t.Fatalf("jobs = %v", names)
	}
	actionsInOrder(t, h.auditText(t), "change.create", "change.capture", "job.create", "change.capture", "job.arm", "job.finish", "change.capture", "job.arm", "change.report")
}

func TestChangeValidationAndOfflineReport(t *testing.T) {
	h := newHarness(t, nil)
	ch := v1.NewChangeServiceClient(h.conn)
	if _, err := ch.CreateChange(ctx(t), &v1.CreateChangeRequest{Spec: &v1.JobSpec{Targets: []*v1.Target{h.target}, DefaultCredentialId: "x"}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("without vault: %v", err)
	}
	h.ready(t)
	if _, err := ch.CreateChange(ctx(t), &v1.CreateChangeRequest{Spec: &v1.JobSpec{Targets: []*v1.Target{h.target}}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("without credential: %v", err)
	}
	if _, err := ch.GetChangeReport(ctx(t), &v1.GetChangeReportRequest{PreDir: "rel", PostDir: "/x"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("relative dirs: %v", err)
	}
	if _, err := ch.GetChangeReport(ctx(t), &v1.GetChangeReportRequest{PreDir: h.out, PostDir: h.out}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("dir without manifest: %v", err)
	}
	if _, err := ch.CaptureChange(ctx(t), &v1.CaptureChangeRequest{ChangeId: "nope", Phase: v1.ChangePhase_CHANGE_PHASE_PRE}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown change: %v", err)
	}
}

func TestUpgradeAndComplianceChecks(t *testing.T) {
	h := newHarness(t, nil)
	ch := v1.NewChangeServiceClient(h.conn)
	caps, _ := os.ReadFile("../upgrade/testdata/c9600-install-sso.txt")
	r, err := ch.CheckUpgrade(ctx(t), &v1.CheckUpgradeRequest{Outputs: string(caps), ImageFile: "cat9k_iosxe.17.12.04.SPA.bin", ImageSize: 1197445748, ImageMd5: "7c2fe5e8a1f6a8e4ad3cd1c7a2d1b0e9"})
	if err != nil || !json.Valid([]byte(r.Report.Json)) || !strings.Contains(r.Report.Text, "verify /md5 bootflash:cat9k_iosxe.17.12.04.SPA.bin") {
		t.Fatalf("upgrade = %+v %v", r, err)
	}
	if _, err := ch.CheckUpgrade(ctx(t), &v1.CheckUpgradeRequest{Outputs: "nada reconocible", ImageFile: "x.bin"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("garbage outputs: %v", err)
	}
	if _, err := ch.CheckUpgrade(ctx(t), &v1.CheckUpgradeRequest{Outputs: string(caps), ImageFile: "x.bin", ImageMd5: "corto"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad md5: %v", err)
	}
	cfg, _ := os.ReadFile("../compliance/testdata/debil.txt")
	tpl, _ := os.ReadFile("../compliance/testdata/plantilla.txt")
	cr, err := ch.CheckCompliance(ctx(t), &v1.CheckComplianceRequest{Config: string(cfg), Template: string(tpl)})
	if err != nil || !strings.Contains(cr.Report.Text, "FALLA") || !json.Valid([]byte(cr.Report.Json)) {
		t.Fatalf("compliance = %+v %v", cr, err)
	}
	if _, err := ch.CheckCompliance(ctx(t), &v1.CheckComplianceRequest{Config: string(cfg), Template: "+ ("}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad template: %v", err)
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `"action":"upgrade.check"`) || !strings.Contains(txt, `"action":"compliance.check"`) {
		t.Fatal("checks not audited")
	}
}
