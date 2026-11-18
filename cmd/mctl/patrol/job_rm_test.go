package patrol

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc/ipctest"
)

type fakePatrol struct {
	v1.UnimplementedPatrolServiceServer
	rm      *v1.RemoveJobsRequest
	rmResp  *v1.RemoveJobsResponse
	rmErr   error
	list    *v1.ListJobsRequest
	listing []*v1.JobSummary
}

func (f *fakePatrol) RemoveJobs(_ context.Context, r *v1.RemoveJobsRequest) (*v1.RemoveJobsResponse, error) {
	f.rm = r
	return f.rmResp, f.rmErr
}

func (f *fakePatrol) ListJobs(_ context.Context, r *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	f.list = r
	return &v1.ListJobsResponse{Jobs: f.listing}, nil
}

func run(t *testing.T, f *fakePatrol, fn func(*cli.Env, []string) error, args ...string) (string, error) {
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
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterPatrolServiceServer(r, f) })
	conn, err := ipc.DialPath(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var out bytes.Buffer
	err = fn(&cli.Env{Out: &out, Conn: conn}, args)
	return out.String(), err
}

func TestJobRmImprimeQuitadosYSaltadosYSaleBienConSaltados(t *testing.T) {
	f := &fakePatrol{rmResp: &v1.RemoveJobsResponse{Removed: 1, RemovedIds: []string{"a"},
		Skipped: []*v1.SkippedJob{{JobId: "b", Reason: "active"}}}}
	out, err := run(t, f, jobRm, "a", "b", "zz")
	if err != nil {
		t.Fatalf("con saltados debe salir bien: %v", err)
	}
	if got := f.rm.GetJobIds(); len(got) != 3 || got[0] != "a" || f.rm.AllFinished {
		t.Errorf("pedido: %v", f.rm)
	}
	if !strings.Contains(out, "a") || !strings.Contains(out, "b") || !strings.Contains(out, "active") {
		t.Errorf("salida: %q", out)
	}
	lineas := strings.Split(strings.TrimSpace(out), "\n")
	if len(lineas) != 2 || strings.Contains(lineas[0], "active") || !strings.Contains(lineas[1], "active") {
		t.Errorf("quitados y saltados van en líneas distintas: %q", out)
	}
}

func TestJobRmErroresDelNucleoSalenConError(t *testing.T) {
	for _, c := range []codes.Code{codes.InvalidArgument, codes.Internal} {
		f := &fakePatrol{rmErr: status.Error(c, "x")}
		if _, err := run(t, f, jobRm, "a"); status.Code(err) != c {
			t.Errorf("%v: %v", c, err)
		}
	}
}

func TestJobRmSinIdsNoLlamaAlNucleo(t *testing.T) {
	f := &fakePatrol{}
	if _, err := run(t, f, jobRm); err == nil || f.rm != nil {
		t.Fatalf("err=%v rm=%v", err, f.rm)
	}
}

func TestJobClearExigeFinished(t *testing.T) {
	f := &fakePatrol{rmResp: &v1.RemoveJobsResponse{Removed: 2, RemovedIds: []string{"a", "b"}}}
	if _, err := run(t, f, jobClear); err == nil || f.rm != nil {
		t.Fatalf("sin --finished: err=%v rm=%v", err, f.rm)
	}
	out, err := run(t, f, jobClear, "--finished")
	if err != nil || !f.rm.AllFinished || len(f.rm.JobIds) != 0 || !strings.Contains(out, "a") {
		t.Fatalf("%v %v %q", err, f.rm, out)
	}
}

func TestJobListPorOmisionNoPidePasadosYAllSi(t *testing.T) {
	fin := time.Date(2026, 11, 6, 15, 4, 5, 0, time.UTC)
	f := &fakePatrol{listing: []*v1.JobSummary{{JobId: "a", Name: "n", State: "closed", FinishedAt: timestamppb.New(fin)}, {JobId: "b", Name: "m", State: "armed"}}}
	out, err := run(t, f, jobList)
	if err != nil || f.list.IncludePast {
		t.Fatalf("por omisión: %v %v", err, f.list)
	}
	if !strings.Contains(out, "2026-11-06") {
		t.Errorf("sin finished_at: %q", out)
	}
	if _, err := run(t, f, jobList, "--all"); err != nil || !f.list.IncludePast {
		t.Fatalf("--all: %v %v", err, f.list)
	}
}
