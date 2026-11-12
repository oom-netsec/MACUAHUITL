package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type keyedAnalysis struct {
	v1.UnimplementedAnalysisServiceServer
}

func (keyedAnalysis) AnalyzeJob(context.Context, *v1.AnalyzeJobRequest) (*v1.AnalyzeJobResponse, error) {
	return &v1.AnalyzeJobResponse{Report: &v1.ToolReport{Json: `{"findings":[]}`, Text: "t", Keys: map[string]*v1.TextRef{"findings.0.detail": {Key: "analyze.detail.lines", Args: map[string]string{"n": "2"}}}}}, nil
}

// Los métodos *Report llevan el texto y las claves; sin claves el campo no viaja (omitempty).
func TestReportesConClaves(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterAnalysisServiceServer(r, keyedAnalysis{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	r, err := b.AnalysisRunReport("j", 0, "")
	if err != nil || r.Text != "t" || r.Keys["findings.0.detail"].Key != "analyze.detail.lines" || r.Keys["findings.0.detail"].Args["n"] != "2" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := b.AnalysisRunReport("j", -1, ""); err == nil {
		t.Error("ronda negativa aceptada")
	}
	if _, err := b.AnalysisDiffReport("j", 0, 2, ""); err == nil {
		t.Error("rondas inválidas aceptadas")
	}
	if _, err := b.DriftRunReport("j", -1, ""); err == nil {
		t.Error("ronda negativa aceptada")
	}
	for name, v := range map[string]any{
		"report": toReport(&v1.ToolReport{Json: "{}"}),
		"fleet":  func() FleetDTO { d, _ := fleetDTO(&v1.ToolReport{Json: "{}"}, nil); return d }(),
		"acl":    AclFindingDTO{Index: 1, Kind: "k", Detail: "d"},
	} {
		raw, _ := json.Marshal(v)
		if s := string(raw); strings.Contains(s, "keys") || strings.Contains(s, "detailKey") || strings.Contains(s, "detailArgs") {
			t.Errorf("%s: campos nuevos sin dato: %s", name, s)
		}
	}
}
