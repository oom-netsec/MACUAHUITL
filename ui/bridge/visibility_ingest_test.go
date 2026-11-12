package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// fakeVisOpts guarda lo que pidió la interfaz y devuelve un archivo nuevo y descartes.
type fakeVisOpts struct {
	v1.UnimplementedVisibilityServiceServer
	traps chan *v1.SnmpTrapsRequest
	flows chan *v1.FlowsRequest
}

var dropsMsg = &v1.SyslogDrops{Total: 7, PorOrigen: 5, Global: 1, ColaLlena: 1, SinceMs: 1793959200000, Top: []*v1.SyslogSourceDrops{{Source: "10.0.0.9", Count: 6}}}

func (f fakeVisOpts) SnmpTraps(r *v1.SnmpTrapsRequest, st v1.VisibilityService_SnmpTrapsServer) error {
	f.traps <- r
	st.Send(&v1.SnmpTrapsResponse{Listening: "127.0.0.1:1162", OutputPath: "/o/snmp-traps"})
	st.Send(&v1.SnmpTrapsResponse{RotatedPath: "/o/snmp-traps/a.jsonl"})
	st.Send(&v1.SnmpTrapsResponse{Drops: dropsMsg})
	<-st.Context().Done()
	return nil
}

func (f fakeVisOpts) Flows(r *v1.FlowsRequest, st v1.VisibilityService_FlowsServer) error {
	f.flows <- r
	st.Send(&v1.FlowsResponse{Listening: "127.0.0.1:2055", OutputPath: "/o/flows"})
	st.Send(&v1.FlowsResponse{RotatedPath: "/o/flows/a.jsonl"})
	st.Send(&v1.FlowsResponse{Drops: dropsMsg})
	<-st.Context().Done()
	return nil
}

const dropsJSON = `"drops":{"total":7,"porOrigen":5,"global":1,"colaLlena":1,"sinceMs":1793959200000,"top":[{"source":"10.0.0.9","count":6}]}`

func TestTrapsAndFlowsBridgeOptionsAndEvents(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := fakeVisOpts{traps: make(chan *v1.SnmpTrapsRequest, 1), flows: make(chan *v1.FlowsRequest, 1)}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterVisibilityServiceServer(r, f) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	if _, err := b.TrapsStart("127.0.0.1:1162", false, true, "", "", "", SyslogOptions{RatePerSource: 4294967396}); err == nil {
		t.Fatal("traps: un valor fuera de int32 se truncó en silencio")
	}
	if _, err := b.FlowsStart("127.0.0.1:2055", false, true, 10, SyslogOptions{MaxFiles: -4294967295}); err == nil {
		t.Fatal("flows: un valor fuera de int32 se truncó en silencio")
	}
	if _, err := b.FlowsStart("127.0.0.1:2055", false, true, 4294967306, SyslogOptions{}); err == nil {
		t.Fatal("flows: top fuera de int32 se truncó en silencio")
	}
	o := SyslogOptions{RatePerSource: 50, BurstPerSource: 60, RateGlobal: 500, BurstGlobal: 600, QueueSize: 128, RotateMB: 5, RotateMinutes: 10, NameTemplate: "x_{fecha}", MaxFiles: 3, Format: "jsonl"}
	tid, err := b.TrapsStart("127.0.0.1:1162", false, true, "c1", "SHA", "AES", o)
	if err != nil {
		t.Fatal(err)
	}
	tr := <-f.traps
	if tr.RatePerSource != 50 || tr.BurstPerSource != 60 || tr.RateGlobal != 500 || tr.BurstGlobal != 600 || tr.QueueSize != 128 || tr.RotateMb != 5 || tr.RotateMinutes != 10 ||
		tr.NameTemplate != "x_{fecha}" || tr.MaxFiles != 3 || tr.Format != "jsonl" || !tr.Save || tr.V3CredentialId != "c1" || tr.AuthProtocol != "SHA" || tr.PrivProtocol != "AES" {
		t.Fatalf("request de traps = %+v", tr)
	}
	rec.waitFor(t, `traps:msg {"json":"","listening":"","outputPath":"","rotatedPath":"/o/snmp-traps/a.jsonl","runId":"`+tid+`"}`)
	rec.waitFor(t, `traps:msg {`+dropsJSON+`,"json":"","listening":"","outputPath":"","rotatedPath":"","runId":"`+tid+`"}`)
	b.DiagCancel(tid)
	fid, err := b.FlowsStart("127.0.0.1:2055", false, true, 10, o)
	if err != nil {
		t.Fatal(err)
	}
	fr := <-f.flows
	if fr.RatePerSource != 50 || fr.BurstPerSource != 60 || fr.RateGlobal != 500 || fr.BurstGlobal != 600 || fr.QueueSize != 128 || fr.RotateMb != 5 || fr.RotateMinutes != 10 ||
		fr.NameTemplate != "x_{fecha}" || fr.MaxFiles != 3 || fr.Format != "jsonl" || !fr.Save || fr.Top != 10 {
		t.Fatalf("request de flows = %+v", fr)
	}
	rec.waitFor(t, `flows:msg {"final":false,"json":"","listening":"","outputPath":"","rotatedPath":"/o/flows/a.jsonl","runId":"`+fid+`"}`)
	rec.waitFor(t, `flows:msg {`+dropsJSON+`,"final":false,"json":"","listening":"","outputPath":"","rotatedPath":"","runId":"`+fid+`"}`)
	b.DiagCancel(fid)
}
