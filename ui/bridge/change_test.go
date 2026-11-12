package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeChange struct {
	v1.UnimplementedChangeServiceServer
	got chan any
}

func (f fakeChange) CreateChange(_ context.Context, r *v1.CreateChangeRequest) (*v1.CreateChangeResponse, error) {
	f.got <- r
	return &v1.CreateChangeResponse{ChangeId: "ch1"}, nil
}

func (f fakeChange) CaptureChange(_ context.Context, r *v1.CaptureChangeRequest) (*v1.CaptureChangeResponse, error) {
	f.got <- r
	return &v1.CaptureChangeResponse{JobId: "j1", Detail: "Login Test falló"}, nil
}

func (fakeChange) ListChanges(context.Context, *v1.ListChangesRequest) (*v1.ListChangesResponse, error) {
	return &v1.ListChangesResponse{Changes: []*v1.ChangeSummary{{ChangeId: "ch1", Name: "crq", PreJobId: "j1", PreState: "completed"}}}, nil
}

func (f fakeChange) GetChangeReport(_ context.Context, r *v1.GetChangeReportRequest) (*v1.GetChangeReportResponse, error) {
	f.got <- r
	return &v1.GetChangeReportResponse{Report: &v1.ToolReport{Json: `{"devices":[]}`, Text: "ok"}}, nil
}

func (f fakeChange) CheckUpgrade(_ context.Context, r *v1.CheckUpgradeRequest) (*v1.CheckUpgradeResponse, error) {
	f.got <- r
	return &v1.CheckUpgradeResponse{Report: &v1.ToolReport{Text: "upgrade"}}, nil
}

func (f fakeChange) CheckCompliance(_ context.Context, r *v1.CheckComplianceRequest) (*v1.CheckComplianceResponse, error) {
	f.got <- r
	return &v1.CheckComplianceResponse{Report: &v1.ToolReport{Text: "cumple"}}, nil
}

func TestChangeBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fc := fakeChange{got: make(chan any, 1)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterChangeServiceServer(r, fc) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)

	id, err := b.ChangeCreate(`{"name":"crq","targets":[{"address":"192.0.2.1"}],"defaultCredentialId":"c1"}`)
	if err != nil || id != "ch1" {
		t.Fatalf("%q %v", id, err)
	}
	if r := (<-fc.got).(*v1.CreateChangeRequest); r.Spec.Name != "crq" || r.Spec.Targets[0].Address != "192.0.2.1" {
		t.Fatalf("create = %+v", r)
	}
	cp, err := b.ChangeCapture("ch1", "post", []string{"SHA256:x"}, nil)
	if err != nil || cp.JobID != "j1" || cp.Armed || cp.Detail == "" {
		t.Fatalf("capture = %+v %v", cp, err)
	}
	if r := (<-fc.got).(*v1.CaptureChangeRequest); r.Phase != v1.ChangePhase_CHANGE_PHASE_POST || r.AcceptedHostKeyFingerprints[0] != "SHA256:x" {
		t.Fatalf("capture req = %+v", r)
	}
	if _, err := b.ChangeCapture("ch1", "durante", nil, nil); err == nil {
		t.Fatal("unknown phase accepted")
	}
	ls, err := b.ListChanges()
	if err != nil || len(ls) != 1 || ls[0].PreState != "completed" {
		t.Fatalf("list = %+v %v", ls, err)
	}
	rep, err := b.ChangeReport("ch1", "", "")
	if err != nil || rep.Json != `{"devices":[]}` {
		t.Fatalf("report = %+v %v", rep, err)
	}
	<-fc.got
	if rep, err := b.UpgradeCheck(UpgradeDTO{Outputs: "SW#show version", Image: "x.bin", Size: 10, MD5: "ab"}); err != nil || rep.Text != "upgrade" {
		t.Fatalf("upgrade = %+v %v", rep, err)
	}
	if r := (<-fc.got).(*v1.CheckUpgradeRequest); r.ImageFile != "x.bin" || r.ImageSize != 10 {
		t.Fatalf("upgrade req = %+v", r)
	}
	if rep, err := b.ComplianceCheck("hostname x", "+ hostname x"); err != nil || rep.Text != "cumple" {
		t.Fatalf("compliance = %+v %v", rep, err)
	}
	<-fc.got
}
