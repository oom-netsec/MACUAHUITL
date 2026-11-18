package patrol

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

var at = timestamppb.New(time.Date(2026, 11, 18, 4, 13, 9, 0, time.UTC))

type horaPatrol struct {
	v1.UnimplementedPatrolServiceServer
}

func (horaPatrol) ArmJob(context.Context, *v1.ArmJobRequest) (*v1.ArmJobResponse, error) {
	return &v1.ArmJobResponse{WindowEndsAt: at}, nil
}
func (horaPatrol) ListJobs(context.Context, *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	return &v1.ListJobsResponse{Jobs: []*v1.JobSummary{{JobId: "j1", Name: "n", State: "completed", FinishedAt: at}}}, nil
}

type horaEvents struct {
	v1.UnimplementedEventServiceServer
}

func (horaEvents) Subscribe(_ *v1.SubscribeRequest, st v1.EventService_SubscribeServer) error {
	return st.Send(&v1.SubscribeResponse{JobId: "j", At: at, Event: &v1.SubscribeResponse_DeviceStateChanged{DeviceStateChanged: &v1.DeviceStateChanged{DeviceId: "d1"}}})
}

// pantalla corre fn contra un núcleo falso y devuelve lo impreso, con la zona de pantalla fija en CST.
func pantalla(t *testing.T, fn func(*cli.Env) error) string {
	t.Helper()
	old := i18n.DisplayZone
	i18n.DisplayZone = time.FixedZone("CST", -6*3600)
	t.Cleanup(func() { i18n.DisplayZone = old })
	d, _ := os.MkdirTemp("", "mh")
	defer os.RemoveAll(d)
	sock := ipctest.Addr(d)
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) {
		v1.RegisterPatrolServiceServer(r, horaPatrol{})
		v1.RegisterEventServiceServer(r, horaEvents{})
	})
	conn, err := ipc.DialPath(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var out bytes.Buffer
	if err := fn(&cli.Env{Out: &out, Conn: conn}); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestHoraLocalConZonaEnJobWatchListYArm(t *testing.T) {
	for name, fn := range map[string]func(*cli.Env) error{
		"watch": func(c *cli.Env) error { return jobWatch(c, []string{"j"}) },
		"list":  func(c *cli.Env) error { return jobList(c, nil) },
		"arm":   func(c *cli.Env) error { return jobArm(c, []string{"j"}) },
	} {
		if out := pantalla(t, fn); !strings.Contains(out, "2026-11-17 22:13") || !strings.Contains(out, " CST") {
			t.Errorf("%s: sin hora local con zona: %q", name, out)
		}
	}
}
