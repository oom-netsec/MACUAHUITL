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

type fakeVis struct {
	v1.UnimplementedVisibilityServiceServer
	topo chan *v1.BuildTopologyRequest
	get  chan *v1.SnmpGetRequest
}

func (f fakeVis) BuildTopology(_ context.Context, r *v1.BuildTopologyRequest) (*v1.BuildTopologyResponse, error) {
	f.topo <- r
	return &v1.BuildTopologyResponse{Report: &v1.ToolReport{Json: `{"nodes":[]}`, Text: "topo"}, Svg: "<svg/>"}, nil
}

func (f fakeVis) SnmpGet(_ context.Context, r *v1.SnmpGetRequest) (*v1.SnmpGetResponse, error) {
	f.get <- r
	return &v1.SnmpGetResponse{Report: &v1.ToolReport{Text: "snmp ok"}}, nil
}

func (fakeVis) Flows(r *v1.FlowsRequest, st v1.VisibilityService_FlowsServer) error {
	st.Send(&v1.FlowsResponse{Listening: "127.0.0.1:2055"})
	st.Send(&v1.FlowsResponse{Json: `{"Flows":1}`})
	<-st.Context().Done()
	return nil
}

func (fakeVis) SnmpTraps(r *v1.SnmpTrapsRequest, st v1.VisibilityService_SnmpTrapsServer) error {
	st.Send(&v1.SnmpTrapsResponse{Listening: "127.0.0.1:1162"})
	return nil // termina solo: debe llegar traps:done
}

func TestVisibilityBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fv := fakeVis{topo: make(chan *v1.BuildTopologyRequest, 2), get: make(chan *v1.SnmpGetRequest, 1)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterVisibilityServiceServer(r, fv) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)

	r, err := b.TopoBuild("/tmp/trabajo", "")
	if err != nil || r.Svg != "<svg/>" || r.Text != "topo" || r.Json == "" {
		t.Fatalf("%+v %v", r, err)
	}
	if q := <-fv.topo; q.Dir != "/tmp/trabajo" || q.JobId != "" {
		t.Fatalf("request = %+v", q)
	}
	b.TopoBuild("abc123", "/tmp/c.pcap")
	if q := <-fv.topo; q.JobId != "abc123" || q.PcapPath != "/tmp/c.pcap" {
		t.Fatalf("request = %+v", q)
	}

	txt, err := b.SnmpGet(SnmpTargetDTO{Host: "10.0.0.1", Version: "3", CredentialId: "c1", Auth: "SHA", Priv: "AES"}, []string{"1.3.6.1.2.1.1.5.0"})
	if err != nil || txt != "snmp ok" {
		t.Fatalf("%q %v", txt, err)
	}
	if q := <-fv.get; q.Target.Version != "3" || q.Target.CredentialId != "c1" || q.Target.PrivProtocol != "AES" {
		t.Fatalf("request = %+v", q)
	}

	id, err := b.FlowsStart("127.0.0.1:2055", false, false, 10, SyslogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for rec.count("flows:msg") < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if err := b.DiagCancel(id); err != nil {
		t.Fatal(err)
	}
	if _, err := b.TrapsStart("127.0.0.1:1162", false, false, "", "", "", SyslogOptions{}); err != nil {
		t.Fatal(err)
	}
	for (rec.count("flows:done") == 0 || rec.count("traps:done") == 0) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if rec.count("flows:msg") != 2 || rec.count("flows:done") != 1 || rec.count("traps:msg") != 1 || rec.count("traps:done") != 1 {
		t.Fatalf("events = %v", rec.evs)
	}
}
