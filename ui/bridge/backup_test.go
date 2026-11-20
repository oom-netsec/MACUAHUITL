package bridge

import (
	"context"
	"os"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

type fakeBackup struct {
	v1.UnimplementedBackupServiceServer
	got *v1.StartBackupRequest
}

func (f *fakeBackup) StartBackup(_ context.Context, r *v1.StartBackupRequest) (*v1.StartBackupResponse, error) {
	f.got = r
	if r.JobId != "" { // rearmado: devuelve las mismas huellas pendientes
		return &v1.StartBackupResponse{JobId: r.JobId, Reason: "patrol.svc.login_failed", HostKeys: []*v1.PendingHostKey{{Host: "[2001:db8::1]:2222", Fingerprint: "SHA256:f", KeyType: "ssh-ed25519", Changed: true}}}, nil
	}
	return &v1.StartBackupResponse{JobId: "j1", Armed: true}, nil
}
func (fakeBackup) CollectBackups(_ context.Context, r *v1.CollectBackupsRequest) (*v1.CollectBackupsResponse, error) {
	return &v1.CollectBackupsResponse{State: "completed", Done: true, Report: &v1.ToolReport{Json: `{"saved":[]}`, Text: r.JobId}}, nil
}
func (fakeBackup) ListBackups(_ context.Context, r *v1.ListBackupsRequest) (*v1.ListBackupsResponse, error) {
	return &v1.ListBackupsResponse{Report: &v1.ToolReport{Json: `{"device":"` + r.Device + `"}`}}, nil
}
func (fakeBackup) GetBackup(_ context.Context, r *v1.GetBackupRequest) (*v1.GetBackupResponse, error) {
	return &v1.GetBackupResponse{MetaJson: `{"id":"` + r.Id + `"}`, Text: "hostname SW1\n"}, nil
}
func (fakeBackup) DiffBackups(_ context.Context, r *v1.DiffBackupsRequest) (*v1.DiffBackupsResponse, error) {
	return &v1.DiffBackupsResponse{Report: &v1.ToolReport{Json: r.From + ">" + r.To}}, nil
}

func TestBackupBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := ipctest.Addr(d)
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fb := &fakeBackup{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterBackupServiceServer(r, fb) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, (&recorder{}).emit)
	Start(ctx, b)
	st, err := b.BackupStart([]AdhocTargetDTO{{Address: "192.0.2.1", Port: 2222}}, "c1", true, 7, 3600, 3, false, []string{"SHA256:x"}, nil, "")
	if err != nil || !st.Armed || st.JobID != "j1" || len(fb.got.Targets) != 1 || fb.got.Targets[0].Port != 2222 || !fb.got.Startup || fb.got.Keep != 7 || fb.got.IntervalSeconds != 3600 || fb.got.Rounds != 3 || fb.got.IncludeSecrets {
		t.Fatalf("start %+v %v %+v", st, err, fb.got)
	}
	if st.HostKeys == nil || len(st.HostKeys) != 0 {
		t.Fatalf("hostKeys debe ser un arreglo vacío, no nulo: %#v", st.HostKeys)
	}
	st, err = b.BackupStart(nil, "", false, 0, 0, 0, false, nil, []AcceptedHostKeyDTO{{Host: "h", Fingerprint: "SHA256:y"}}, "j7")
	want := PendingHostKeyDTO{Host: "[2001:db8::1]:2222", Fingerprint: "SHA256:f", KeyType: "ssh-ed25519", Changed: true}
	if err != nil || fb.got.JobId != "j7" || fb.got.AcceptedHostKeys[0].Fingerprint != "SHA256:y" || st.JobID != "j7" || st.Armed || st.Reason != "patrol.svc.login_failed" || len(st.HostKeys) != 1 || st.HostKeys[0] != want {
		t.Fatalf("rearmado %+v %v %+v", st, err, fb.got)
	}
	if c, err := b.BackupCollect("j1"); err != nil || !c.Done || c.Text != "j1" || c.Json != `{"saved":[]}` {
		t.Fatalf("collect %+v %v", c, err)
	}
	if js, err := b.BackupList("sw1"); err != nil || js != `{"device":"sw1"}` {
		t.Fatalf("list %q %v", js, err)
	}
	if g, err := b.BackupGet("a/b"); err != nil || g.Text != "hostname SW1\n" || g.Meta != `{"id":"a/b"}` {
		t.Fatalf("get %+v %v", g, err)
	}
	if js, err := b.BackupDiff("x", "y"); err != nil || js != "x>y" {
		t.Fatalf("diff %q %v", js, err)
	}
}
