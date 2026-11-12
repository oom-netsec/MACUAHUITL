package bridge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeForensic struct {
	v1.UnimplementedForensicServiceServer
}

func (fakeForensic) MsgLookup(_ context.Context, r *v1.MsgLookupRequest) (*v1.MsgLookupResponse, error) {
	return &v1.MsgLookupResponse{Report: &v1.ToolReport{Json: `[{"id":"` + r.Query + `"}]`}}, nil
}
func (fakeForensic) Crashinfo(_ context.Context, r *v1.CrashinfoRequest) (*v1.CrashinfoResponse, error) {
	return &v1.CrashinfoResponse{Report: &v1.ToolReport{Json: `{"text":"` + r.Text + `","path":"` + r.Path + `"}`}}, nil
}

func (fakeForensic) LogPatterns(_ context.Context, r *v1.LogPatternsRequest) (*v1.LogPatternsResponse, error) {
	return &v1.LogPatternsResponse{Report: &v1.ToolReport{Json: fmt.Sprintf(`{"t":%q,"p":%q,"c":%v,"j":%q,"d":%q,"k":%d,"n":%d,"w":%d}`, r.Source.Text, r.Source.Path, r.Source.Capture, r.Source.Job, r.Source.Device, r.Source.MaxKib, r.BurstCount, r.BurstWindowSeconds)}}, nil
}

func (fakeForensic) Flapping(_ context.Context, r *v1.FlappingRequest) (*v1.FlappingResponse, error) {
	return &v1.FlappingResponse{Report: &v1.ToolReport{Json: fmt.Sprintf(`{"j":%q,"n":%d,"w":%d,"m":%d}`, r.Source.Job, r.Count, r.WindowSeconds, r.MinDelta)}}, nil
}

func (fakeForensic) DebugFilter(_ context.Context, r *v1.DebugFilterRequest) (*v1.DebugFilterResponse, error) {
	return &v1.DebugFilterResponse{Report: &v1.ToolReport{Json: fmt.Sprintf(`{"t":%q,"p":%q,"n":%q,"f":%d,"r":%d,"top":%d}`, r.Text, r.Path, r.Noise, r.FamilyMin, r.RareMax, r.Top)}}, nil
}

func (fakeForensic) MemLeaks(_ context.Context, r *v1.MemLeaksRequest) (*v1.MemLeaksResponse, error) {
	return &v1.MemLeaksResponse{Report: &v1.ToolReport{Json: fmt.Sprintf(`{"j":%q,"d":%q,"r":%d,"k":%d}`, r.Job, r.Device, r.MinRounds, r.MinGrowthKib)}}, nil
}

func TestForensicBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterForensicServiceServer(r, fakeForensic{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	if js, err := b.ForensicMsg("%SYS-2-X"); err != nil || js != `[{"id":"%SYS-2-X"}]` {
		t.Fatalf("msg %q %v", js, err)
	}
	if js, err := b.ForensicCrashinfo("t", "/p"); err != nil || js != `{"text":"t","path":"/p"}` {
		t.Fatalf("crashinfo %q %v", js, err)
	}
	if js, err := b.ForensicPatterns(LogSourceDTO{Job: "j1", Device: "sw1"}, 7, 30); err != nil || js != `{"t":"","p":"","c":false,"j":"j1","d":"sw1","k":0,"n":7,"w":30}` {
		t.Fatalf("patterns %q %v", js, err)
	}
	if js, err := b.ForensicPatterns(LogSourceDTO{Capture: true, MaxKiB: 4096}, 0, 0); err != nil || !strings.Contains(js, `"c":true`) || !strings.Contains(js, `"k":4096`) {
		t.Fatalf("max_kib no llegó: %s %v", js, err)
	}
	if _, err := b.ForensicPatterns(LogSourceDTO{Capture: true}, -1, 0); err == nil {
		t.Fatal("ráfaga negativa aceptada")
	}
	if js, err := b.ForensicFlapping(LogSourceDTO{Job: "j1"}, 4, 30, 9); err != nil || js != `{"j":"j1","n":4,"w":30,"m":9}` {
		t.Fatalf("flapping %q %v", js, err)
	}
	if _, err := b.ForensicFlapping(LogSourceDTO{Capture: true}, 0, 0, -1); err == nil {
		t.Fatal("delta negativo aceptado")
	}
	if js, err := b.ForensicDebugs("x", "", []string{"cdp", "ntp"}, 30, 1, 5); err != nil || js != `{"t":"x","p":"","n":["cdp" "ntp"],"f":30,"r":1,"top":5}` {
		t.Fatalf("debugs %q %v", js, err)
	}
	if _, err := b.ForensicDebugs("x", "", nil, 0, -1, 0); err == nil {
		t.Fatal("umbral negativo aceptado")
	}
	if js, err := b.ForensicLeaks("j1", "sw1", 4, 2048); err != nil || js != `{"j":"j1","d":"sw1","r":4,"k":2048}` {
		t.Fatalf("leaks %q %v", js, err)
	}
	if _, err := b.ForensicLeaks("j1", "", -1, 0); err == nil {
		t.Fatal("rondas negativas aceptadas")
	}
}
