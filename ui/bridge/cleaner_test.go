package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeCleaner struct {
	v1.UnimplementedCleanerServiceServer
}

func (fakeCleaner) Clean(_ context.Context, r *v1.CleanRequest) (*v1.CleanResponse, error) {
	o := r.Text
	if r.Sort {
		o += "+orden"
	}
	return &v1.CleanResponse{Report: &v1.ToolReport{Json: `{"changes":[]}`, Text: "t"}, Output: o}, nil
}

func TestCleanerBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterCleanerServiceServer(r, fakeCleaner{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	if r, err := b.CleanerRun("cfg", true); err != nil || r.Output != "cfg+orden" || r.Json != `{"changes":[]}` || r.Text != "t" {
		t.Fatalf("clean %+v %v", r, err)
	}
	if r, err := b.CleanerRun("cfg", false); err != nil || r.Output != "cfg" {
		t.Fatalf("clean %+v %v", r, err)
	}
}
