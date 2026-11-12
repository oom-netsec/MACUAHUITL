package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeCalc struct {
	v1.UnimplementedCalcServiceServer
	got chan any
}

var calcOut = &v1.CalcResult{Text: "ok", Notes: []string{"n"}, Tables: []*v1.CalcTable{{Title: "T", Head: []string{"a"}, Rows: []*v1.CalcRow{{Cells: []string{"1"}}}}}}

func (f fakeCalc) Mtu(_ context.Context, r *v1.MtuRequest) (*v1.MtuResponse, error) {
	f.got <- r
	return &v1.MtuResponse{Result: calcOut}, nil
}

func (f fakeCalc) Bgp(_ context.Context, r *v1.BgpRequest) (*v1.BgpResponse, error) {
	f.got <- r
	return &v1.BgpResponse{Result: calcOut}, nil
}

func TestCalcBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fc := fakeCalc{got: make(chan any, 1)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterCalcServiceServer(r, fc) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	res, err := b.Calc("mtu", `{"physical":1500,"layers":["gre","mpls:2"],"innerIpv6":true}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.Text != "ok" || len(res.Tables) != 1 || res.Tables[0].Rows[0][0] != "1" || res.Notes[0] != "n" {
		t.Fatalf("%+v", res)
	}
	if r := (<-fc.got).(*v1.MtuRequest); r.Physical != 1500 || len(r.Layers) != 2 || !r.InnerIpv6 {
		t.Fatalf("request = %+v", r)
	}
	if _, err := b.Calc("bgp", `{"routes":[{"name":"A","localPref":200,"asPath":"65001"}],"deterministicMed":true}`); err != nil {
		t.Fatal(err)
	}
	if r := (<-fc.got).(*v1.BgpRequest); r.Routes[0].GetLocalPref() != 200 || r.Routes[0].Med != nil || !r.DeterministicMed {
		t.Fatalf("request = %+v", r)
	}
	if _, err := b.Calc("frob", `{}`); err == nil {
		t.Fatal("calculadora desconocida aceptada")
	}
	if _, err := b.Calc("mtu", `{"physical":"x"}`); err == nil {
		t.Fatal("JSON inválido aceptado")
	}
}
