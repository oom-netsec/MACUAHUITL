package bridge

import (
	"context"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeHistorial anota lo que llega al núcleo y devuelve un trabajo pasado y un omitido.
type fakeHistorial struct {
	v1.UnimplementedPatrolServiceServer
	list   chan *v1.ListJobsRequest
	remove chan *v1.RemoveJobsRequest
}

func (f fakeHistorial) ListJobs(_ context.Context, r *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	f.list <- r
	return &v1.ListJobsResponse{Jobs: []*v1.JobSummary{{JobId: "j1", State: "completed", Past: true,
		FinishedAt: timestamppb.New(time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)),
		Phases: []*v1.JobPhase{
			{Kind: v1.JobPhaseKind_JOB_PHASE_KIND_ARM_FAILED, Reason: "patrol.svc.login_failed", Args: map[string]string{"failed": "10.0.0.1:22: AUTH"}, Detail: "raw"},
			{Kind: v1.JobPhaseKind_JOB_PHASE_KIND_ARM_FAILED, Reason: "x.reason_nuevo", Detail: "core text"},
			{Kind: v1.JobPhaseKind_JOB_PHASE_KIND_ARM_FAILED, Detail: "dial tcp: timeout"},
		}}}}, nil
}

func (f fakeHistorial) RemoveJobs(_ context.Context, r *v1.RemoveJobsRequest) (*v1.RemoveJobsResponse, error) {
	f.remove <- r
	return &v1.RemoveJobsResponse{Removed: 1, RemovedIds: []string{"j1"}, Skipped: []*v1.SkippedJob{{JobId: "j2", Reason: "change_pre"}}}, nil
}

func TestHistorial46(t *testing.T) {
	f := fakeHistorial{list: make(chan *v1.ListJobsRequest, 1), remove: make(chan *v1.RemoveJobsRequest, 1)}
	b, _ := startServices(t, func(r ipc.Registrar) { v1.RegisterPatrolServiceServer(r, f) })

	jobs, err := b.ListJobs(ListJobsOpts{IncludePast: true})
	if err != nil {
		t.Fatal(err)
	}
	if !(<-f.list).IncludePast {
		t.Fatal("includePast no llegó al núcleo")
	}
	if len(jobs) != 1 || !jobs[0].Past || jobs[0].FinishedAt != "2026-11-16T10:00:00Z" {
		t.Fatalf("JobDTO sin past/finishedAt: %+v", jobs)
	}
	// Un reason del catálogo del núcleo llega traducido en detail (la UI no tiene ese catálogo); sin reason o con uno
	// desconocido queda el texto del núcleo.
	ph := jobs[0].Phases
	if want := i18n.Msg(b.locale(), "patrol.svc.login_failed", i18n.Args{"failed": "10.0.0.1:22: AUTH"}); len(ph) != 3 || ph[0].Detail != want || !strings.Contains(want, "10.0.0.1:22: AUTH") {
		t.Fatalf("fase con reason del catálogo: %+v", ph)
	}
	if ph[0].Reason != "patrol.svc.login_failed" || ph[0].Kind != "JOB_PHASE_KIND_ARM_FAILED" || ph[1].Detail != "core text" || ph[2].Detail != "dial tcp: timeout" {
		t.Fatalf("fases: %+v", ph)
	}

	// La UI solo elige ids: «todos los terminados» no se puede pedir desde la UI (quita exactamente lo confirmado).
	res, err := b.RemoveJobs(RemoveJobsSel{JobIDs: []string{"j1", "j2"}})
	if err != nil {
		t.Fatal(err)
	}
	if r := <-f.remove; len(r.JobIds) != 2 || r.AllFinished {
		t.Fatalf("RemoveJobsRequest = %v", r)
	}
	if res.Removed != 1 || len(res.RemovedIDs) != 1 || len(res.Skipped) != 1 || res.Skipped[0].JobID != "j2" || res.Skipped[0].Reason != "change_pre" {
		t.Fatalf("RemoveJobs = %+v", res)
	}
	if jsonOf(t, res) != `{"removed":1,"removedIds":["j1"],"skipped":[{"jobId":"j2","reason":"change_pre"}]}` {
		t.Fatalf("JSON = %s", jsonOf(t, res))
	}
}
