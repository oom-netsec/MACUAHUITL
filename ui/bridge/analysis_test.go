package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeAnalysis struct {
	v1.UnimplementedAnalysisServiceServer
	tl chan *v1.TimelineRequest
}

func (fakeAnalysis) AnalyzeJob(_ context.Context, r *v1.AnalyzeJobRequest) (*v1.AnalyzeJobResponse, error) {
	return &v1.AnalyzeJobResponse{Report: &v1.ToolReport{Json: `{"job":"` + r.Job + `"}`, Text: "texto"}}, nil
}

func (fakeAnalysis) DiffRounds(_ context.Context, r *v1.DiffRoundsRequest) (*v1.DiffRoundsResponse, error) {
	return &v1.DiffRoundsResponse{Report: &v1.ToolReport{Json: `{"from":1}`}}, nil
}

func (f fakeAnalysis) Timeline(_ context.Context, r *v1.TimelineRequest) (*v1.TimelineResponse, error) {
	f.tl <- r
	return &v1.TimelineResponse{Report: &v1.ToolReport{Json: `{"events":[]}`}}, nil
}

func TestAnalysisBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fa := fakeAnalysis{tl: make(chan *v1.TimelineRequest, 1)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterAnalysisServiceServer(r, fa) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	// La UI recibe el JSON del reporte, no el texto.
	if js, err := b.AnalysisRun("j1", 2, ""); err != nil || js != `{"job":"j1"}` {
		t.Fatalf("run %q %v", js, err)
	}
	if js, err := b.AnalysisDiff("j1", 1, 2, ""); err != nil || js != `{"from":1}` {
		t.Fatalf("diff %q %v", js, err)
	}
	if _, err := b.AnalysisDiff("j1", -1, 2, ""); err == nil {
		t.Fatal("negative round accepted")
	}
	if _, err := b.AnalysisTimeline("j1", "2026-11-04T10:09:18Z", 45, "RTR2", "/x.pcap"); err != nil {
		t.Fatal(err)
	}
	r := <-fa.tl
	if !r.Around.AsTime().Equal(time.Date(2026, 11, 4, 10, 9, 18, 0, time.UTC)) || r.WindowSeconds != 45 || r.Device != "RTR2" || r.PcapPath != "/x.pcap" {
		t.Fatalf("timeline request = %+v", r)
	}
	if _, err := b.AnalysisTimeline("j1", "ayer", 30, "", ""); err == nil {
		t.Fatal("bad instant accepted")
	}
	if _, err := b.AnalysisTimeline("j1", "", 0, "", ""); err != nil {
		t.Fatal(err)
	}
	if r := <-fa.tl; r.Around != nil {
		t.Fatalf("empty instant sent: %+v", r.Around)
	}
}
