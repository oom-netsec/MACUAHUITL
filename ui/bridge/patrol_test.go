package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeIfaces struct {
	v1.UnimplementedDiagServiceServer
}

func (fakeIfaces) ListInterfaces(context.Context, *v1.ListInterfacesRequest) (*v1.ListInterfacesResponse, error) {
	return &v1.ListInterfacesResponse{Interfaces: []*v1.NetInterface{
		{Name: "eth0", Up: true, Addresses: []string{"192.0.2.10/24"}, HardwareAddr: "00:11:22:33:44:55"},
		{Name: "lo", Up: true, Loopback: true},
	}}, nil
}

// startServices sirve los servicios dados en un socket temporal y devuelve un puente conectado.
func startServices(t *testing.T, reg func(ipc.Registrar)) (*Bridge, *recorder) {
	t.Helper()
	d, _ := os.MkdirTemp("", "brg")
	t.Cleanup(func() { os.RemoveAll(d) })
	sock := filepath.Join(d, "core.sock")
	l, err := ipc.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go ipc.Serve(ctx, l, reg)
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)
	return b, rec
}

func jsonOf(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestListInterfacesDTO(t *testing.T) {
	b, _ := startServices(t, func(r ipc.Registrar) { v1.RegisterDiagServiceServer(r, fakeIfaces{}) })
	got, err := b.ListInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"name":"eth0","up":true,"loopback":false,"addresses":["192.0.2.10/24"],"hardwareAddr":"00:11:22:33:44:55"},` +
		`{"name":"lo","up":true,"loopback":true,"addresses":[],"hardwareAddr":""}]`
	if s := jsonOf(t, got); s != want {
		t.Fatalf("json = %s", s)
	}
}

var t0 = time.Date(2026, 11, 4, 18, 0, 0, 0, time.UTC)

type fakePatrol struct {
	v1.UnimplementedPatrolServiceServer
}

func (fakePatrol) ListJobs(context.Context, *v1.ListJobsRequest) (*v1.ListJobsResponse, error) {
	return &v1.ListJobsResponse{Jobs: []*v1.JobSummary{
		{JobId: "j1", Name: "caso-1", State: "armed", NextRoundAt: timestamppb.New(t0.Add(time.Hour)), ArmedAt: timestamppb.New(t0),
			WindowEndsAt: timestamppb.New(t0.Add(4 * time.Hour)), Round: 1, Rounds: 3, DevicesTotal: 4, DevicesOk: 3, DevicesFailed: 1, OutputDir: "/o/caso-1_x", Kind: "backup",
			Phases: []*v1.JobPhase{{At: timestamppb.New(t0), Kind: v1.JobPhaseKind_JOB_PHASE_KIND_ARMED, Detail: "4 equipos"},
				{At: timestamppb.New(t0.Add(time.Minute)), Kind: v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_FINISHED, Round: 1, Detail: "3 correctos, 1 con fallas"}}},
		{JobId: "j2", Name: "nuevo", State: "created", Rounds: 1},
	}}, nil
}

type fakePhaseEvents struct {
	v1.UnimplementedEventServiceServer
}

func (fakePhaseEvents) Subscribe(r *v1.SubscribeRequest, st v1.EventService_SubscribeServer) error {
	st.Send(&v1.SubscribeResponse{At: timestamppb.New(t0), JobId: "j1", Event: &v1.SubscribeResponse_PhaseAdded{
		PhaseAdded: &v1.JobPhase{At: timestamppb.New(t0), Kind: v1.JobPhaseKind_JOB_PHASE_KIND_ROUND_STARTED, Round: 2}}})
	<-st.Context().Done()
	return nil
}

func TestJobDTOAndPhaseEvent(t *testing.T) {
	b, rec := startServices(t, func(r ipc.Registrar) {
		v1.RegisterPatrolServiceServer(r, fakePatrol{})
		v1.RegisterEventServiceServer(r, fakePhaseEvents{})
	})
	jobs, err := b.ListJobs()
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"id":"j1","name":"caso-1","state":"armed","nextRoundAt":"2026-11-04T19:00:00Z","armedAt":"2026-11-04T18:00:00Z",` +
		`"windowEndsAt":"2026-11-04T22:00:00Z","round":1,"rounds":3,"devicesTotal":4,"devicesOk":3,"devicesFailed":1,"outputDir":"/o/caso-1_x","kind":"backup",` +
		`"phases":[{"at":"2026-11-04T18:00:00Z","kind":"JOB_PHASE_KIND_ARMED","round":0,"detail":"4 equipos"},` +
		`{"at":"2026-11-04T18:01:00Z","kind":"JOB_PHASE_KIND_ROUND_FINISHED","round":1,"detail":"3 correctos, 1 con fallas"}]},` +
		`{"id":"j2","name":"nuevo","state":"created","nextRoundAt":"","armedAt":"","windowEndsAt":"","round":0,"rounds":1,` +
		`"devicesTotal":0,"devicesOk":0,"devicesFailed":0,"outputDir":"","kind":"","phases":[]}]`
	if s := jsonOf(t, jobs); s != want {
		t.Fatalf("json =\n%s\nwant\n%s", s, want)
	}
	if err := b.Subscribe(context.Background(), []string{"j1"}); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `core:event {"at":"2026-11-04T18:00:00Z","jobId":"j1","phaseAdded":{"at":"2026-11-04T18:00:00Z","kind":"JOB_PHASE_KIND_ROUND_STARTED","round":2}}`)
}

type fakePlaybooks struct {
	v1.UnimplementedPatrolServiceServer
}

func (fakePlaybooks) ListPlaybooks(_ context.Context, r *v1.ListPlaybooksRequest) (*v1.ListPlaybooksResponse, error) {
	return &v1.ListPlaybooksResponse{Playbooks: []*v1.PlaybookInfo{
		{Id: "ios-xe/stp", Platform: "ios-xe", Name: "STP", Commands: []string{"show spanning-tree", "show version"}},
	}}, nil
}

func TestListPlaybooksJSON(t *testing.T) {
	b, _ := startServices(t, func(r ipc.Registrar) { v1.RegisterPatrolServiceServer(r, fakePlaybooks{}) })
	got, err := b.ListPlaybooks()
	if err != nil {
		t.Fatal(err)
	}
	// protojson mete espacios al azar: se compara el JSON ya decodificado.
	var g any
	if err := json.Unmarshal([]byte(got), &g); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"playbooks": []any{map[string]any{"id": "ios-xe/stp", "platform": "ios-xe", "name": "STP",
		"commands": []any{"show spanning-tree", "show version"}}}}
	if !reflect.DeepEqual(g, want) {
		t.Fatalf("json = %s", got)
	}
}

func TestTargetLabel(t *testing.T) {
	// Igual que el deviceId de los eventos del núcleo (patrol.hostport), si no la fila no se actualiza.
	if got := targetLabel("192.168.3.2", 2222); got != "192.168.3.2:2222" {
		t.Fatalf("puerto 2222: %q", got)
	}
	if got := targetLabel("fe80::1", 22); got != "[fe80::1]:22" {
		t.Fatalf("IPv6: %q", got)
	}
	if got := targetLabel("sw-core", 22); got != "sw-core:22" {
		t.Fatalf("nombre: %q", got)
	}
}
