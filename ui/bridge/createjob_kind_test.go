package bridge

import (
	"context"
	"os"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

type fakePatrolKind struct {
	v1.UnimplementedPatrolServiceServer
	got chan *v1.JobSpec
}

func (f fakePatrolKind) CreateJob(_ context.Context, r *v1.CreateJobRequest) (*v1.CreateJobResponse, error) {
	f.got <- r.Spec
	return &v1.CreateJobResponse{JobId: "j1"}, nil
}

// La UI no elige el tipo de trabajo: un JobSpec con kind llega al núcleo con kind vacío.
func TestCreateJobVaciaElKind(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := ipctest.Addr(d)
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	f := fakePatrolKind{got: make(chan *v1.JobSpec, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterPatrolServiceServer(r, f) })
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, func(string, any) {})
	for _, k := range []string{"backup", "change", "adhoc", "patrol"} {
		if _, err := b.CreateJob(`{"name":"x","kind":"` + k + `"}`); err != nil {
			t.Fatal(err)
		}
		if sp := <-f.got; sp.Kind != "" || sp.Name != "x" {
			t.Fatalf("kind=%q name=%q: el núcleo debe recibir el kind vacío y el resto intacto", sp.Kind, sp.Name)
		}
	}
}
