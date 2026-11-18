package backup

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

type fakeBackup struct {
	v1.UnimplementedBackupServiceServer
	got *v1.CollectBackupsRequest
}

func (f *fakeBackup) CollectBackups(_ context.Context, r *v1.CollectBackupsRequest) (*v1.CollectBackupsResponse, error) {
	f.got = r
	return &v1.CollectBackupsResponse{State: "completed", Done: true, Report: &v1.ToolReport{}}, nil
}

func runCollect(t *testing.T, f *fakeBackup, args ...string) error {
	t.Helper()
	d, _ := os.MkdirTemp("", "mw")
	defer os.RemoveAll(d)
	sock := ipctest.Addr(d)
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterBackupServiceServer(r, f) })
	conn, err := ipc.DialPath(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return collect(&cli.Env{Out: &bytes.Buffer{}, Conn: conn}, args)
}

func TestCollectConDirPasaLaCarpetaYNoPideTrabajo(t *testing.T) {
	f := &fakeBackup{}
	if err := runCollect(t, f, "--dir", "/srv/run1", "--keep", "5"); err != nil {
		t.Fatal(err)
	}
	if f.got.Dir != "/srv/run1" || f.got.JobId != "" || f.got.Keep != 5 {
		t.Errorf("pedido: %v", f.got)
	}
}

func TestCollectNoAceptaTrabajoYDirJuntosNiNinguno(t *testing.T) {
	for _, args := range [][]string{{"j1", "--dir", "/x"}, {}} {
		f := &fakeBackup{}
		if err := runCollect(t, f, args...); err == nil || f.got != nil {
			t.Errorf("%v: err=%v got=%v", args, err, f.got)
		}
	}
	f := &fakeBackup{}
	if err := runCollect(t, f, "j1"); err != nil || f.got.JobId != "j1" || f.got.Dir != "" {
		t.Errorf("por id: %v %v", err, f.got)
	}
}
