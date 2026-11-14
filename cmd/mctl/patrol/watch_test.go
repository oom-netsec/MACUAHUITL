package patrol

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type endEvents struct {
	v1.UnimplementedEventServiceServer
	send []string
}

func (f endEvents) Subscribe(_ *v1.SubscribeRequest, st v1.EventService_SubscribeServer) error {
	for _, s := range f.send {
		st.Send(&v1.SubscribeResponse{JobId: "j", Event: &v1.SubscribeResponse_JobStateChanged{JobStateChanged: &v1.JobStateChanged{State: s}}})
	}
	return nil // el servidor cierra el stream: el cliente ve io.EOF
}

func watchWith(t *testing.T, send ...string) (string, error) {
	t.Helper()
	d, _ := os.MkdirTemp("", "mw")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "c.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterEventServiceServer(r, endEvents{send: send}) })
	conn, err := ipc.DialPath(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var out bytes.Buffer
	err = jobWatch(&cli.Env{Out: &out, Conn: conn}, []string{"j"})
	return out.String(), err
}

// job watch termina bien con el closed y también si el servidor cierra el stream (io.EOF): no es un error.
func TestJobWatchTerminaBienConClosedYConEOF(t *testing.T) {
	if _, err := watchWith(t, "completed", "closed"); err != nil {
		t.Fatalf("con closed: %v", err)
	}
	if _, err := watchWith(t, "completed"); err != nil {
		t.Fatalf("con EOF: %v", err)
	}
}
