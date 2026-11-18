package devices

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

type horaInv struct {
	v1.UnimplementedInventoryServiceServer
}

func (horaInv) ListDevices(context.Context, *v1.ListDevicesRequest) (*v1.ListDevicesResponse, error) {
	return &v1.ListDevicesResponse{Devices: []*v1.Device{{Hostname: "sw1", LastSeenMs: time.Date(2026, 11, 18, 4, 13, 0, 0, time.UTC).UnixMilli()}}}, nil
}

func TestDevicesHoraLocalConZona(t *testing.T) {
	old := i18n.DisplayZone
	i18n.DisplayZone = time.FixedZone("CST", -6*3600)
	defer func() { i18n.DisplayZone = old }()
	d, _ := os.MkdirTemp("", "md")
	defer os.RemoveAll(d)
	sock := ipctest.Addr(d)
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterInventoryServiceServer(r, horaInv{}) })
	conn, err := ipc.DialPath(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var out bytes.Buffer
	if err := list(&cli.Env{Out: &out, Conn: conn}, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "2026-11-17 22:13 CST") {
		t.Errorf("%q", out.String())
	}
}
