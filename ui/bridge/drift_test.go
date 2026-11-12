package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeDrift struct {
	v1.UnimplementedDriftServiceServer
}

func (fakeDrift) Drift(_ context.Context, r *v1.DriftRequest) (*v1.DriftResponse, error) {
	return &v1.DriftResponse{Report: &v1.ToolReport{Json: `{"job":"` + r.Job + `","round":` + string(rune('0'+r.Round)) + `,"device":"` + r.Device + `"}`}}, nil
}

func TestDriftBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterDriftServiceServer(r, fakeDrift{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	if js, err := b.DriftRun("j1", 2, "sw1"); err != nil || js != `{"job":"j1","round":2,"device":"sw1"}` {
		t.Fatalf("drift %q %v", js, err)
	}
	if _, err := b.DriftRun("j1", -1, ""); err == nil {
		t.Fatal("ronda negativa aceptada")
	}
}
