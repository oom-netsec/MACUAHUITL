package bridge

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

type fakeAssist struct {
	v1.UnimplementedAssistServiceServer
	mu         sync.Mutex
	assisted   []bool
	confirms   []string
	activeOnly []bool
	rotSecret  string
	platforms  []string
}

func (f *fakeAssist) PlanPorts(_ context.Context, r *v1.PlanPortsRequest) (*v1.PlanPortsResponse, error) {
	d := &v1.AssistDevicePlan{Device: r.Target.Name, Apply: []string{"interface " + r.Interfaces[0]}, Rollback: []string{"x"}}
	return &v1.PlanPortsResponse{PlanId: "p1", Plan: &v1.AssistPlan{Function: "ports", Devices: []*v1.AssistDevicePlan{d}}}, nil
}

func (f *fakeAssist) PlanSnippet(_ context.Context, r *v1.PlanSnippetRequest) (*v1.PlanSnippetResponse, error) {
	kind := "vlan"
	if r.GetTrunk() != nil {
		kind = "trunk " + r.GetTrunk().Op
	}
	if t := r.GetTemplate(); t != nil {
		kind = "template " + t.Id + " " + t.Values["speed"]
	}
	d := &v1.AssistDevicePlan{Device: r.Target.Name, Apply: []string{kind}, Rollback: []string{"x"}}
	return &v1.PlanSnippetResponse{PlanId: "s1", Plan: &v1.AssistPlan{Function: "snippet", Devices: []*v1.AssistDevicePlan{d}}}, nil
}

func (f *fakeAssist) ListSnippetTemplates(_ context.Context, r *v1.ListSnippetTemplatesRequest) (*v1.ListSnippetTemplatesResponse, error) {
	f.mu.Lock()
	f.platforms = append(f.platforms, r.Platform)
	f.mu.Unlock()
	return &v1.ListSnippetTemplatesResponse{Templates: []*v1.SnippetTemplate{{Id: "speed-duplex", Tech: "l2", Name: "Velocidad y duplex", Platforms: []string{"ios"},
		Fields: []*v1.SnippetField{{Name: "speed", Label: "Velocidad", Type: "choice", Choices: []string{"auto", "100"}, DefaultValue: "auto"}}}}}, nil
}

func (f *fakeAssist) PlanCredRotate(_ context.Context, r *v1.PlanCredRotateRequest) (*v1.PlanCredRotateResponse, error) {
	f.mu.Lock()
	f.rotSecret = r.NewSecret
	f.mu.Unlock()
	d := &v1.AssistDevicePlan{Device: r.Target.Name, Apply: []string{"username " + r.User + " secret <oculto>"}, Rollback: []string{"x"}}
	return &v1.PlanCredRotateResponse{PlanId: "c1", Plan: &v1.AssistPlan{Function: "credrotate", Devices: []*v1.AssistDevicePlan{d}}}, nil
}

func (f *fakeAssist) PlanRestore(_ context.Context, r *v1.PlanRestoreRequest) (*v1.PlanRestoreResponse, error) {
	if r.BackupId == "SW1/rechazado" {
		return &v1.PlanRestoreResponse{Reason: "no", Refused: []*v1.RestoreRefusal{{Line: "vtp mode client", Why: "vtp"}}}, nil
	}
	d := &v1.AssistDevicePlan{Device: r.Target.Name, Apply: []string{"restore " + r.BackupId}, Rollback: []string{"x"}}
	return &v1.PlanRestoreResponse{PlanId: "rs1", Plan: &v1.AssistPlan{Function: "restore-diff", Devices: []*v1.AssistDevicePlan{d}}}, nil
}

func (f *fakeAssist) StartRun(_ context.Context, r *v1.StartRunRequest) (*v1.StartRunResponse, error) {
	f.mu.Lock()
	f.assisted = append(f.assisted, r.Assisted)
	f.mu.Unlock()
	return &v1.StartRunResponse{RunId: "r1"}, nil
}

func (f *fakeAssist) WatchRun(_ *v1.WatchRunRequest, st v1.AssistService_WatchRunServer) error {
	st.Send(&v1.WatchRunResponse{Event: &v1.AssistEvent{Kind: "pending", Step: &v1.AssistStep{Id: "apply-1", Lines: []string{"shutdown"}}}})
	return st.Send(&v1.WatchRunResponse{Event: &v1.AssistEvent{Kind: "state", State: "done"}})
}

func (f *fakeAssist) ListRuns(_ context.Context, r *v1.ListRunsRequest) (*v1.ListRunsResponse, error) {
	f.mu.Lock()
	f.activeOnly = append(f.activeOnly, r.ActiveOnly)
	f.mu.Unlock()
	return &v1.ListRunsResponse{Runs: []*v1.AssistRunState{{RunId: "r1", State: "waiting-confirm", Active: true, Changed: []string{"SW1"}}}}, nil
}

func (f *fakeAssist) Confirm(_ context.Context, r *v1.ConfirmRequest) (*v1.ConfirmResponse, error) {
	f.mu.Lock()
	f.confirms = append(f.confirms, r.RunId+"/"+r.StepId)
	f.mu.Unlock()
	return &v1.ConfirmResponse{}, nil
}

func TestAssistBridge(t *testing.T) {
	d, _ := os.MkdirTemp("", "brg")
	defer os.RemoveAll(d)
	sock := filepath.Join(d, "core.sock")
	l, _ := ipc.Listen(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fa := &fakeAssist{}
	go ipc.Serve(ctx, l, func(r ipc.Registrar) { v1.RegisterAssistServiceServer(r, fa) })
	rec := &recorder{}
	b := New(func() (*ipc.ClientConn, error) { return ipc.DialPath(sock) }, rec.emit)
	Start(ctx, b)

	out, err := b.AssistPlanPorts(`{"target":{"name":"SW1","address":"10.0.0.1","credentialId":"c1"},"interfaces":["Gi1/0/1"],"vlan":20,"description":"","shutdown":false}`)
	if err != nil || !strings.Contains(out, `"planId":"p1"`) || !strings.Contains(out, "interface Gi1/0/1") {
		t.Fatalf("plan %q %v", out, err)
	}
	sn, err := b.AssistPlanSnippet(`{"target":{"name":"SW1","address":"10.0.0.1","credentialId":"c1"},"trunk":{"interface":"Gi1/0/48","op":"add","vlan":30}}`)
	if err != nil || !strings.Contains(sn, `"planId":"s1"`) || !strings.Contains(sn, "trunk add") {
		t.Fatalf("snippet %q %v", sn, err)
	}
	if _, err := b.AssistPlanSnippet(`{"trunk":{"interface":"Gi1/0/48","op":"add","vlan":30},"vlan":{"id":30}}`); err == nil {
		t.Fatal("dos snippets a la vez")
	}
	// Una plantilla del catálogo: el puente solo reenvía sus valores; el núcleo los valida.
	tp, err := b.AssistPlanSnippet(`{"target":{"name":"SW1","address":"10.0.0.1","credentialId":"c1"},"template":{"id":"speed-duplex","values":{"interfaces":"Gi1/0/1","speed":"100"}}}`)
	if err != nil || !strings.Contains(tp, "template speed-duplex 100") {
		t.Fatalf("plantilla %q %v", tp, err)
	}
	lt, err := b.AssistListSnippetTemplates("ios-xe")
	var cat struct {
		Templates []struct {
			ID     string
			Fields []struct {
				Choices      []string
				DefaultValue string
			}
		}
	}
	if err != nil || json.Unmarshal([]byte(lt), &cat) != nil || len(cat.Templates) != 1 || cat.Templates[0].ID != "speed-duplex" ||
		cat.Templates[0].Fields[0].DefaultValue != "auto" || len(cat.Templates[0].Fields[0].Choices) != 2 {
		t.Fatalf("catálogo %q %v", lt, err)
	}
	fa.mu.Lock()
	if len(fa.platforms) != 1 || fa.platforms[0] != "ios-xe" {
		t.Fatalf("plataformas %v", fa.platforms)
	}
	fa.mu.Unlock()
	rs, err := b.AssistPlanRestore(`{"target":{"name":"SW1","address":"10.0.0.1","credentialId":"c1"},"backupId":"SW1/20261106T100000Z-running","allowPartial":true}`)
	if err != nil || !strings.Contains(rs, `"planId":"rs1"`) || !strings.Contains(rs, "restore SW1/20261106T100000Z-running") {
		t.Fatalf("restaurar %q %v", rs, err)
	}
	if rs, err = b.AssistPlanRestore(`{"target":{"name":"SW1","address":"10.0.0.1","credentialId":"c1"},"backupId":"SW1/rechazado"}`); err != nil || strings.Contains(rs, "planId") || !strings.Contains(rs, "vtp mode client") {
		t.Fatalf("rechazado %q %v", rs, err)
	}
	if _, err := b.AssistPlanRestore(`{"backup":"x"}`); err == nil {
		t.Fatal("JSON con campos desconocidos")
	}
	// El secreto nuevo llega al núcleo y nunca vuelve en la respuesta.
	rot, err := b.AssistPlanCredRotate(`{"target":{"name":"SW1","address":"10.0.0.1","credentialId":"c1"},"user":"tech","newSecret":"Nuev0-Secreto.2026","updateCredentialId":"c2"}`)
	if err != nil || !strings.Contains(rot, `"planId":"c1"`) || strings.Contains(rot, "Nuev0-Secreto") {
		t.Fatalf("rotación %q %v", rot, err)
	}
	fa.mu.Lock()
	got := fa.rotSecret
	fa.mu.Unlock()
	if got != "Nuev0-Secreto.2026" {
		t.Fatalf("el núcleo no recibió el secreto: %q", got)
	}
	if n := rec.countPrefix("assist:"); n != 0 {
		t.Fatalf("planear no emite eventos: %d", n)
	}
	if _, err := b.AssistPlanPorts(`{"nope":1}`); err == nil {
		t.Fatal("JSON con campos desconocidos")
	}
	// La bandera viaja tal cual: el puente no la enciende por su cuenta.
	if run, err := b.AssistStart("p1", false); err != nil || run != "r1" {
		t.Fatalf("start %q %v", run, err)
	}
	if run, err := b.AssistStart("p1", true); err != nil || run != "r1" {
		t.Fatalf("start %q %v", run, err)
	}
	// Hallazgo 7: AssistStart solo devuelve el id; los eventos llegan cuando la vista pide verlos (AssistWatch).
	time.Sleep(100 * time.Millisecond)
	if n := rec.countPrefix("assist:"); n != 0 {
		t.Fatalf("AssistStart emitió %d eventos antes de que la vista supiera el id", n)
	}
	if err := b.AssistWatch("r1"); err != nil {
		t.Fatal(err)
	}
	rec.waitFor(t, `assist:done {"runId":"r1"}`)
	rec.waitFor(t, `assist:event {"event":{"kind":"pending","step":{"id":"apply-1","lines":["shutdown"]}},"runId":"r1"}`)
	if err := b.AssistConfirm("r1", "apply-1"); err != nil {
		t.Fatal(err)
	}
	// Hallazgo 6: la vista busca ejecuciones vivas al montarse.
	out, err = b.AssistListRuns()
	if err != nil || !strings.Contains(out, `"runId":"r1"`) || !strings.Contains(out, `"changed":["SW1"]`) {
		t.Fatalf("runs %q %v", out, err)
	}
	fa.mu.Lock()
	defer fa.mu.Unlock()
	if len(fa.activeOnly) != 1 || !fa.activeOnly[0] {
		t.Fatalf("ListRuns sin activeOnly: %v", fa.activeOnly)
	}
	if len(fa.assisted) != 2 || fa.assisted[0] || !fa.assisted[1] || len(fa.confirms) != 1 || fa.confirms[0] != "r1/apply-1" {
		t.Fatalf("assisted=%v confirms=%v", fa.assisted, fa.confirms)
	}
}

func (r *recorder) countPrefix(p string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.evs {
		if strings.HasPrefix(e, p) {
			n++
		}
	}
	return n
}
