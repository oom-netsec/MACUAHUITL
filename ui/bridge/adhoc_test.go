package bridge

import (
	"context"
	"os"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

type fakeAdhoc struct {
	v1.UnimplementedAdhocServiceServer
	got *v1.StartAdhocRequest
}

func (f *fakeAdhoc) StartAdhoc(_ context.Context, r *v1.StartAdhocRequest) (*v1.StartAdhocResponse, error) {
	f.got = r
	if r.Commands == "sin armar" {
		return &v1.StartAdhocResponse{JobId: "j2", Reason: "patrol.svc.login_failed", HostKeys: []*v1.PendingHostKey{{Host: "10.0.0.1", Fingerprint: "SHA256:f", KeyType: "ssh-rsa"}}}, nil
	}
	return &v1.StartAdhocResponse{JobId: "j1", Armed: true}, nil
}

func (*fakeAdhoc) AdhocResult(context.Context, *v1.AdhocResultRequest) (*v1.AdhocResultResponse, error) {
	return &v1.AdhocResultResponse{State: "completed", Done: true, Report: &v1.ToolReport{Json: `{"rows":[]}`, Text: "t"}, Csv: "a,b", Markdown: "| a |", Error: "disco lleno"}, nil
}

func TestAdhocBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := ipctest.Addr(d)
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeAdhoc{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterAdhocServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	st, err := b.AdhocStart([]AdhocTargetDTO{{Address: "192.0.2.1", Port: 2222}}, "c1", "show clock", []string{"SHA256:x"}, nil)
	if err != nil || !st.Armed || st.JobID != "j1" {
		t.Fatalf("start %+v %v", st, err)
	}
	if len(f.got.Targets) != 1 || f.got.Targets[0].Port != 2222 || f.got.CredentialId != "c1" || f.got.Commands != "show clock" || f.got.AcceptedHostKeyFingerprints[0] != "SHA256:x" {
		t.Fatalf("petición = %+v", f.got)
	}
	if len(st.HostKeys) != 0 || st.HostKeys == nil {
		t.Fatalf("hostKeys debe ser un arreglo vacío, no nulo: %#v", st.HostKeys)
	}
	st, err = b.AdhocStart(nil, "c1", "sin armar", nil, nil)
	if err != nil || st.Armed || st.JobID != "j2" || st.Reason != "patrol.svc.login_failed" || len(st.HostKeys) != 1 || st.HostKeys[0] != (PendingHostKeyDTO{Host: "10.0.0.1", Fingerprint: "SHA256:f", KeyType: "ssh-rsa"}) {
		t.Fatalf("sin armar %+v %v", st, err)
	}
	if r, err := b.AdhocResult("j1"); err != nil || !r.Done || r.Csv != "a,b" || r.Markdown != "| a |" || r.Text != "t" || r.Json != `{"rows":[]}` || r.Error != "disco lleno" {
		t.Fatalf("result %+v %v", r, err)
	}
}
