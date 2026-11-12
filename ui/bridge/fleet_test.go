package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeFleet struct {
	v1.UnimplementedFleetServiceServer
}

func (fakeFleet) Find(_ context.Context, r *v1.FindRequest) (*v1.FindResponse, error) {
	return &v1.FindResponse{Report: &v1.ToolReport{Json: `{"query":"` + r.Query + `"}`, Text: "t"}}, nil
}

func (fakeFleet) Path(_ context.Context, r *v1.PathRequest) (*v1.PathResponse, error) {
	return &v1.PathResponse{Report: &v1.ToolReport{Json: `{"dst":"` + r.Dst + `"}`}, Svg: "<svg/>"}, nil
}

func (fakeFleet) Inventory(context.Context, *v1.InventoryRequest) (*v1.InventoryResponse, error) {
	return &v1.InventoryResponse{Report: &v1.ToolReport{Json: `{}`}, Csv: "a,b", Markdown: "| a |"}, nil
}

func TestFleetBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterFleetServiceServer(r, fakeFleet{}) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	if r, err := b.FleetFind("10.1.1.1"); err != nil || r.Json != `{"query":"10.1.1.1"}` || r.Text != "t" {
		t.Fatalf("find %+v %v", r, err)
	}
	if r, err := b.FleetPath("a", "b"); err != nil || r.Svg != "<svg/>" || r.Json != `{"dst":"b"}` {
		t.Fatalf("path %+v %v", r, err)
	}
	if r, err := b.FleetInventory(); err != nil || r.Csv != "a,b" || r.Markdown != "| a |" {
		t.Fatalf("inv %+v %v", r, err)
	}
	if _, err := b.FleetHealth(); err == nil {
		t.Fatal("el servidor sin implementar debe dar error")
	}
}
