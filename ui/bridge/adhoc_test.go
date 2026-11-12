package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeAdhoc struct {
	v1.UnimplementedAdhocServiceServer
	got *v1.StartAdhocRequest
}

func (f *fakeAdhoc) StartAdhoc(_ context.Context, r *v1.StartAdhocRequest) (*v1.StartAdhocResponse, error) {
	f.got = r
	return &v1.StartAdhocResponse{JobId: "j1", Armed: true}, nil
}

func (*fakeAdhoc) AdhocResult(context.Context, *v1.AdhocResultRequest) (*v1.AdhocResultResponse, error) {
	return &v1.AdhocResultResponse{State: "completed", Done: true, Report: &v1.ToolReport{Json: `{"rows":[]}`, Text: "t"}, Csv: "a,b", Markdown: "| a |", Error: "disco lleno"}, nil
}

func TestAdhocBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := &fakeAdhoc{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterAdhocServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	st, err := b.AdhocStart([]AdhocTargetDTO{{Address: "192.0.2.1", Port: 2222}}, "c1", "show clock", []string{"SHA256:x"})
	if err != nil || !st.Armed || st.JobID != "j1" {
		t.Fatalf("start %+v %v", st, err)
	}
	if len(f.got.Targets) != 1 || f.got.Targets[0].Port != 2222 || f.got.CredentialId != "c1" || f.got.Commands != "show clock" || f.got.AcceptedHostKeyFingerprints[0] != "SHA256:x" {
		t.Fatalf("petición = %+v", f.got)
	}
	if r, err := b.AdhocResult("j1"); err != nil || !r.Done || r.Csv != "a,b" || r.Markdown != "| a |" || r.Text != "t" || r.Json != `{"rows":[]}` || r.Error != "disco lleno" {
		t.Fatalf("result %+v %v", r, err)
	}
}
