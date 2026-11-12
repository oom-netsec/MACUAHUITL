package assist

import (
	"context"
	"errors"
	"fmt"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"google.golang.org/protobuf/reflect/protoreflect"
	"net/netip"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/assist"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const gi1 = "GigabitEthernet1/0/1"

type rig struct {
	t        *testing.T
	svc      *assistSvc
	d        *servicetest.Deps
	rec      *simulator.Recorder
	attempts *atomic.Int32
	target   *v1.AssistTarget
	fp       string
	backups  int64 // respaldos guardados por las pruebas de restauración
}

func newRig(t *testing.T, c simulator.Config) *rig {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	d := servicetest.New(t)
	v := d.CreateVault()
	pw, en := secret.New([]byte("pw")), secret.New([]byte("en"))
	t.Cleanup(func() { pw.Destroy(); en.Destroy() })
	id, err := v.Put(vault.Credential{Label: "lab", Username: "admin", Password: pw, Enable: en})
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, d: d, rec: &simulator.Recorder{}, attempts: &atomic.Int32{}}
	c.Hostname, c.Username, c.Password, c.Enable = "SW1", "admin", "pw", "en"
	c.Transcripts = filepath.Join(filepath.Dir(f), "..", "..", "..", "test", "transcripts", "ios-xe")
	c.Recorder, c.Attempts = r.rec, r.attempts
	if c.Vlans == nil {
		c.Vlans = []int{1, 10, 20, 30, 110, 120}
	}
	if c.Interfaces == nil {
		c.Interfaces = map[string][]string{gi1: {"description Impresora", "switchport access vlan 10", "switchport mode access", "shutdown"}}
	}
	addr, hk := simulator.Start(t, c)
	ap := netip.MustParseAddrPort(addr)
	r.target = &v1.AssistTarget{Name: "SW1", Address: ap.Addr().String(), Port: uint32(ap.Port()), CredentialId: id}
	r.fp = transport.Fingerprint(hk)
	r.svc = newSvc(d)
	t.Cleanup(r.svc.Close)
	return r
}

func (r *rig) plan(ch *v1.PlanPortsRequest) (*v1.PlanPortsResponse, error) {
	ch.Target, ch.AcceptedHostKeyFingerprints = r.target, []string{r.fp}
	if len(ch.Interfaces) == 0 {
		ch.Interfaces = []string{gi1}
	}
	return r.svc.PlanPorts(context.Background(), ch)
}

func (r *rig) start(planID string) string {
	r.t.Helper()
	res, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: planID, Assisted: true})
	if err != nil {
		r.t.Fatal(err)
	}
	return res.RunId
}

func (r *rig) state(run string) *v1.AssistRunState {
	rec, err := r.svc.get(run)
	if err != nil {
		r.t.Fatal(err)
	}
	return snapshot(rec)
}

func (r *rig) waitState(run, want string) *v1.AssistRunState {
	r.t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if s := r.state(run); s.State == want {
			return s
		}
	}
	r.t.Fatalf("estado %s, se esperaba %s", r.state(run).State, want)
	return nil
}

func (r *rig) confirm(run, step string) {
	r.t.Helper()
	if _, err := r.svc.Confirm(context.Background(), &v1.ConfirmRequest{RunId: run, StepId: step}); err != nil {
		r.t.Fatal(err)
	}
}

// closeAndWait confirma el paso de cierre (sin write memory el cambio queda solo en running) y espera done.
func (r *rig) closeAndWait(run string) {
	r.t.Helper()
	if s := r.waitState(run, "waiting-confirm"); s.Pending.GetKind() != "close" {
		r.t.Fatalf("se esperaba el paso de cierre: %+v", s.Pending)
	}
	r.confirm(run, "close")
	r.waitState(run, "done")
}

func (r *rig) waitDone(run string) {
	r.t.Helper()
	rec, _ := r.svc.get(run)
	select {
	case <-rec.finished:
	case <-time.After(5 * time.Second):
		r.t.Fatal("la ejecución no terminó")
	}
}

func code(err error) codes.Code { return status.Code(err) }

func TestPlanPortsIsReadOnlyAndBuildsRollbackFromDevice(t *testing.T) {
	r := newRig(t, simulator.Config{})
	res, err := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	if err != nil {
		t.Fatal(err)
	}
	dp := res.Plan.Devices[0]
	if !reflect.DeepEqual(dp.Apply, []string{"interface " + gi1, "switchport access vlan 20"}) ||
		!reflect.DeepEqual(dp.Rollback, []string{"interface " + gi1, "switchport access vlan 10"}) {
		t.Fatalf("plan = %+v", dp)
	}
	if got := r.rec.Lines(); len(got) != 0 {
		t.Fatalf("planear no puede configurar nada: %q", got)
	}
	if !strings.Contains(r.d.AuditText(), "assist.plan") {
		t.Fatal("el plan no quedó en la bitácora")
	}
}

func TestPlanPortsRefusesTrunk(t *testing.T) {
	r := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"switchport mode trunk"}}})
	if _, err := r.plan(&v1.PlanPortsRequest{Vlan: 20}); code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
	if _, err := r.plan(&v1.PlanPortsRequest{Vlan: 20, Interfaces: []string{"Port-channel1"}}); code(err) != codes.InvalidArgument {
		t.Fatalf("err = %v", err)
	}
}

func TestPlanNeedsHostKeyConfirmation(t *testing.T) {
	r := newRig(t, simulator.Config{})
	_, err := r.svc.PlanPorts(context.Background(), &v1.PlanPortsRequest{Target: r.target, Interfaces: []string{gi1}, Vlan: 20})
	if err == nil || !strings.Contains(err.Error(), r.fp) {
		t.Fatalf("err = %v", err)
	}
}

// Regla 1: sin assisted:true no hay ejecución y no se abre ni una conexión.
func TestStartRunNeedsAssistedFlag(t *testing.T) {
	r := newRig(t, simulator.Config{})
	res, err := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	if err != nil {
		t.Fatal(err)
	}
	before := r.attempts.Load()
	_, err = r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: res.PlanId})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if r.attempts.Load() != before || len(r.rec.Lines()) != 0 || len(r.svc.runs) != 0 {
		t.Fatal("hubo conexión o ejecución sin assisted")
	}
	// El permiso no se hereda: una ejecución con assisted no habilita la siguiente.
	run := r.start(res.PlanId)
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitDone(run)
	res2, _ := r.plan(&v1.PlanPortsRequest{Vlan: 30})
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: res2.PlanId}); code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
	// Un plan inexistente (o ya usado) no arranca nada.
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: res.PlanId, Assisted: true}); code(err) != codes.NotFound {
		t.Fatalf("plan reutilizado: %v", err)
	}
}

type stream struct {
	v1.AssistService_WatchRunServer
	ctx    context.Context
	events []*v1.AssistEvent
}

func (s *stream) Context() context.Context { return s.ctx }
func (s *stream) Send(m *v1.WatchRunResponse) error {
	s.events = append(s.events, m.Event)
	return nil
}

// Reglas 4, 6 y 7 de punta a punta contra el simulador, y el cierre de guard y ventana.
func TestAssistedRunEndToEnd(t *testing.T) {
	r := newRig(t, simulator.Config{})
	res, err := r.plan(&v1.PlanPortsRequest{Vlan: 20, Description: ptr("Telefono")})
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	s := r.waitState(run, "waiting-confirm")
	if s.Pending.Id != "apply-1" || !reflect.DeepEqual(s.Pending.Lines, res.Plan.Devices[0].Apply) {
		t.Fatalf("pendiente = %+v", s.Pending)
	}
	if w := r.d.V.Windows(); len(w) != 1 || w[0].JobID != run {
		t.Fatalf("ventanas = %+v", w)
	}
	time.Sleep(50 * time.Millisecond)
	if len(r.rec.Lines()) != 0 {
		t.Fatalf("se configuró sin confirmar: %q", r.rec.Lines())
	}
	r.confirm(run, "apply-1")
	r.closeAndWait(run)
	r.waitDone(run)
	want := append(append([]string(nil), res.Plan.Devices[0].Apply...), "end")
	if got := r.rec.Lines(); !reflect.DeepEqual(got, want) { // sin "!write memory": regla 7
		t.Fatalf("el equipo recibió %q", got)
	}
	txt := r.d.AuditText()
	for _, w := range []string{"assist.start", "assist.confirm", "assist.line", "run=" + run, "switchport access vlan 20", "assist.done"} {
		if !strings.Contains(txt, w) {
			t.Errorf("la bitácora no tiene %q", w)
		}
	}
	// Cierre: guard revocado y ventana de bóveda cerrada.
	if _, err := r.d.G.Dial(context.Background(), run, r.target.Address, uint16(r.target.Port)); err == nil {
		t.Fatal("el guard sigue abierto para la ejecución")
	}
	if len(r.d.V.Windows()) != 0 {
		t.Fatal("la ventana de la bóveda sigue abierta")
	}
	// WatchRun entrega el historial completo y termina.
	st := &stream{ctx: context.Background()}
	if err := r.svc.WatchRun(&v1.WatchRunRequest{RunId: run}, st); err != nil {
		t.Fatal(err)
	}
	last := st.events[len(st.events)-1]
	if last.Kind != "state" || last.State != "done" {
		t.Fatalf("último evento: %+v", last)
	}
}

func ptr[T any](v T) *T { return &v }

// Regla 5 de punta a punta: error de configuración, parada, reversa exacta con confirmación.
func TestConfigErrorStopsAndRollbackRestoresDevice(t *testing.T) {
	r := newRig(t, simulator.Config{ConfigErrors: map[string]string{"description Telefono": "% Invalid input detected at '^' marker."}})
	first, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20, Description: ptr("Telefono"), Shutdown: ptr(false)})
	run := r.start(first.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	s := r.waitState(run, "failed")
	if !strings.Contains(s.FailReason, "Invalid input") {
		t.Fatalf("motivo %q", s.FailReason)
	}
	for _, l := range r.rec.Lines() { // la línea posterior al error no llegó
		if l == "no shutdown" {
			t.Fatalf("siguió enviando tras el error: %q", r.rec.Lines())
		}
	}
	if _, err := r.svc.Rollback(context.Background(), &v1.RollbackRequest{RunId: run}); err != nil {
		t.Fatal(err)
	}
	if s := r.waitState(run, "waiting-confirm"); s.Pending.Id != "rollback-1" || !reflect.DeepEqual(s.Pending.Lines, first.Plan.Devices[0].Rollback) {
		t.Fatalf("pendiente = %+v", s.Pending)
	}
	r.confirm(run, "rollback-1")
	r.waitState(run, "rolled-back")
	r.waitDone(run)
	// El equipo quedó como estaba: planear de nuevo da la misma reversa.
	again, err := r.plan(&v1.PlanPortsRequest{Vlan: 20, Description: ptr("Telefono"), Shutdown: ptr(false)})
	if err != nil || !reflect.DeepEqual(again.Plan.Devices[0].Rollback, first.Plan.Devices[0].Rollback) {
		t.Fatalf("%v %v", err, again)
	}
}

func TestWriteMemoryOnlyAfterConfirmedStep(t *testing.T) {
	r := newRig(t, simulator.Config{})
	res, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20, WriteMemory: true})
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	if s := r.waitState(run, "waiting-confirm"); s.Pending.Id != "save-1" {
		t.Fatalf("pendiente = %+v", s.Pending)
	}
	for _, l := range r.rec.Lines() {
		if l == "!write memory" {
			t.Fatal("guardó antes de confirmar")
		}
	}
	r.confirm(run, "save-1")
	r.waitState(run, "done")
	if got := r.rec.Lines(); got[len(got)-1] != "!write memory" {
		t.Fatalf("%q", got)
	}
}

func TestStepEndpointsRejectStrangers(t *testing.T) {
	r := newRig(t, simulator.Config{})
	if _, err := r.svc.Confirm(context.Background(), &v1.ConfirmRequest{RunId: "nope", StepId: "apply-1"}); code(err) != codes.NotFound {
		t.Fatalf("err = %v", err)
	}
	res, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	if _, err := r.svc.Confirm(context.Background(), &v1.ConfirmRequest{RunId: run, StepId: "apply-9"}); code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatal("se configuró con un paso equivocado")
	}
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitDone(run)
}

// Regla 3: Pre y Post pasan por CheckDenied también en el ejecutor, antes de abrir conexión.
func TestExecReadRefusesNonReadCommands(t *testing.T) {
	r := newRig(t, simulator.Config{})
	ex := newExec(r.d, "x", nil, transport.HostKeyPolicy{})
	for _, c := range []string{"reload", "configure terminal", "write memory", "show run | redirect flash:x"} {
		if _, err := ex.Read(context.Background(), "SW1", []string{c}); !errors.Is(err, playbook.ErrDenied) {
			t.Errorf("%q: err = %v", c, err)
		}
	}
}

// Regla 1: no existe una preferencia ni un ajuste que encienda el modo asistido.
func TestNoGlobalSwitchForAssistedMode(t *testing.T) {
	for _, f := range []protoreflect.FileDescriptor{v1.File_macuahuitl_v1_prefs_proto, v1.File_macuahuitl_v1_vault_proto, v1.File_macuahuitl_v1_patrol_proto} {
		msgs := f.Messages()
		for i := 0; i < msgs.Len(); i++ {
			fields := msgs.Get(i).Fields()
			for j := 0; j < fields.Len(); j++ {
				if n := strings.ToLower(string(fields.Get(j).Name())); strings.Contains(n, "assist") {
					t.Errorf("%s.%s enciende o recuerda el modo asistido", msgs.Get(i).Name(), n)
				}
			}
		}
	}
	// El único campo de v1 que lo habilita es StartRunRequest.assisted, por petición.
	if f := (&v1.StartRunRequest{}).ProtoReflect().Descriptor().Fields().ByName("assisted"); f == nil {
		t.Fatal("falta StartRunRequest.assisted")
	}
}

func TestExecReadRefusesNonASCII(t *testing.T) {
	r := newRig(t, simulator.Config{})
	ex := newExec(r.d, "x", nil, transport.HostKeyPolicy{})
	for _, c := range []string{"show versionÍ", "show xÊ", "show version\r"} {
		if _, err := ex.Read(context.Background(), "SW1", []string{c}); !errors.Is(err, playbook.ErrDenied) {
			t.Errorf("%q: err = %v", c, err)
		}
	}
}

// Hallazgo 1: si el ingeniero tarda más que el exec-timeout del equipo, la sesión muere; la reversa
// confirmada debe reconectar por el guard y restaurar el equipo.
func TestRollbackReconnectsAfterIdleSessionDies(t *testing.T) {
	r := newRig(t, simulator.Config{IdleTimeout: 300 * time.Millisecond})
	res, err := r.plan(&v1.PlanPortsRequest{Vlan: 20, WriteMemory: true})
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	if s := r.waitState(run, "waiting-confirm"); s.Pending.Id != "save-1" {
		t.Fatalf("pendiente = %+v", s.Pending)
	}
	time.Sleep(700 * time.Millisecond) // la sesión del equipo ya expiró
	if _, err := r.svc.Rollback(context.Background(), &v1.RollbackRequest{RunId: run}); err != nil {
		t.Fatal(err)
	}
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "rollback-1")
	r.waitState(run, "rolled-back")
	r.waitDone(run)
	again, err := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	if err != nil || !reflect.DeepEqual(again.Plan.Devices[0].Rollback, res.Plan.Devices[0].Rollback) {
		t.Fatalf("el equipo no quedó restaurado: %v %v", err, again)
	}
}

// Hallazgo 2: un puerto ruteado sin "no switchport" (administración, NAT) no se planea.
func TestPlanPortsRefusesRoutedPortWithoutNoSwitchport(t *testing.T) {
	for name, body := range map[string][]string{
		"mgmt":   {"vrf forwarding Mgmt-vrf", "ip address 10.1.1.2 255.255.255.0"},
		"router": {"ip address 192.0.2.1 255.255.255.0", "ip nat outside"},
	} {
		r := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: body}})
		if _, err := r.plan(&v1.PlanPortsRequest{Vlan: 20, Shutdown: ptr(true)}); code(err) != codes.FailedPrecondition {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// Hallazgo 5: una VLAN que no existe no se crea; el plan se rechaza y el equipo no recibe nada.
func TestPlanPortsRefusesVlanThatDoesNotExist(t *testing.T) {
	r := newRig(t, simulator.Config{})
	_, err := r.plan(&v1.PlanPortsRequest{Vlan: 99})
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "no existe") {
		t.Fatalf("err = %v", err)
	}
	if _, err := r.plan(&v1.PlanPortsRequest{Voice: 98}); code(err) != codes.FailedPrecondition {
		t.Fatalf("voz: %v", err)
	}
	if len(r.rec.Lines()) != 0 {
		t.Fatalf("se configuró algo: %q", r.rec.Lines())
	}
}

// Hallazgo 5: si el equipo avisa que crea la VLAN, la ejecución se detiene y ofrece la reversa.
func TestCreatingVlanWarningStopsRun(t *testing.T) {
	r := newRig(t, simulator.Config{ConfigErrors: map[string]string{"switchport access vlan 20": "% Access VLAN does not exist. Creating vlan 20"}})
	res, err := r.plan(&v1.PlanPortsRequest{Vlan: 20, Description: ptr("x")})
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	s := r.waitState(run, "failed")
	if !strings.Contains(s.FailReason, "Creating vlan") || len(s.Changed) != 1 {
		t.Fatalf("motivo %q cambiados %v", s.FailReason, s.Changed)
	}
	for _, l := range r.rec.Lines() {
		if l == "description x" {
			t.Fatalf("siguió tras el aviso: %q", r.rec.Lines())
		}
	}
}

// write memory solo cuenta con [OK]; un error de NVRAM detiene la ejecución y deja el equipo como cambiado.
func TestWriteMemoryNeedsOK(t *testing.T) {
	for name, out := range map[string]string{
		"error de nvram": "Building configuration...\n%Error opening nvram:/startup-config (Permission denied)\n",
		"sin OK":         "Building configuration...\n",
	} {
		r := newRig(t, simulator.Config{WriteMemoryOutput: out})
		res, err := r.plan(&v1.PlanPortsRequest{Vlan: 20, WriteMemory: true})
		if err != nil {
			t.Fatal(err)
		}
		run := r.start(res.PlanId)
		r.waitState(run, "waiting-confirm")
		r.confirm(run, "apply-1")
		r.waitState(run, "waiting-confirm")
		r.confirm(run, "save-1")
		s := r.waitState(run, "failed")
		if !strings.Contains(s.FailReason, "write memory") || len(s.Changed) != 1 {
			t.Errorf("%s: motivo %q cambiados %v", name, s.FailReason, s.Changed)
		}
		r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
		r.waitDone(run)
	}
}

// Hallazgo 6: sin decisión en el tiempo tope, la ejecución se abandona: audita qué quedó cambiado,
// cierra la sesión y revoca guard y ventana.
func TestRunAbandonedAfterDecisionTimeout(t *testing.T) {
	r := newRig(t, simulator.Config{})
	r.svc.decisionTimeout = 300 * time.Millisecond
	res, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20, WriteMemory: true})
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	if s := r.waitState(run, "waiting-confirm"); s.Pending.Id != "save-1" {
		t.Fatalf("pendiente %+v", s.Pending)
	}
	s := r.waitState(run, "abandoned")
	if !reflect.DeepEqual(s.Changed, []string{"SW1"}) {
		t.Fatalf("cambiados = %v", s.Changed)
	}
	r.waitDone(run)
	if txt := r.d.AuditText(); !strings.Contains(txt, "assist.abandoned") || !strings.Contains(txt, "changed=SW1") {
		t.Fatalf("la bitácora no dice qué quedó cambiado:\n%s", txt)
	}
	if _, err := r.d.G.Dial(context.Background(), run, r.target.Address, uint16(r.target.Port)); err == nil {
		t.Fatal("el guard sigue abierto")
	}
	if len(r.d.V.Windows()) != 0 {
		t.Fatal("la ventana de la bóveda sigue abierta")
	}
	if _, err := r.svc.Confirm(context.Background(), &v1.ConfirmRequest{RunId: run, StepId: "save-1"}); code(err) != codes.FailedPrecondition {
		t.Fatalf("confirmar tras abandonar: %v", err)
	}
	if st := r.state(run); st.Active {
		t.Fatal("abandonada pero activa")
	}
}

// Hallazgo 6: cerrar el núcleo cancela y espera las ejecuciones, con su estado auditado, antes de cerrar la base.
func TestCloseAbandonsAndAuditsRuns(t *testing.T) {
	r := newRig(t, simulator.Config{})
	res, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20, WriteMemory: true})
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm")
	r.d.OnClose(r.svc.Close)
	r.d.CloseAll()
	if s := r.state(run); s.State != "abandoned" || s.Active {
		t.Fatalf("estado %s activa=%v", s.State, s.Active)
	}
	if txt := r.d.AuditText(); !strings.Contains(txt, "assist.end") || !strings.Contains(txt, "changed=SW1") {
		t.Fatalf("falta la auditoría de cierre:\n%s", txt)
	}
	if len(r.d.V.Windows()) != 0 {
		t.Fatal("la ventana de la bóveda sigue abierta")
	}
	if _, err := r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: "x", Assisted: true}); code(err) != codes.Unavailable {
		t.Fatalf("StartRun tras cerrar: %v", err)
	}
}

// Hallazgo 6: ListRuns y GetAssistRun devuelven lo necesario para volver a una ejecución viva.
func TestListRunsAndGetRunForReattach(t *testing.T) {
	r := newRig(t, simulator.Config{})
	res, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20, WriteMemory: true})
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm")
	l, err := r.svc.ListRuns(context.Background(), &v1.ListRunsRequest{ActiveOnly: true})
	if err != nil || len(l.Runs) != 1 {
		t.Fatalf("%v %v", l, err)
	}
	g, err := r.svc.GetAssistRun(context.Background(), &v1.GetAssistRunRequest{RunId: run})
	if err != nil {
		t.Fatal(err)
	}
	st := g.Run
	if st.RunId != run || !st.Active || !st.Waiting || !st.CanRollback || st.Pending.GetId() != "save-1" || !reflect.DeepEqual(st.Changed, []string{"SW1"}) || st.EventCount == 0 || st.StartedUnix == 0 {
		t.Fatalf("%+v", st)
	}
	// Solo los eventos nuevos desde event_count.
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitDone(run)
	ws := &stream{ctx: context.Background()}
	if err := r.svc.WatchRun(&v1.WatchRunRequest{RunId: run, FromSeq: st.EventCount}, ws); err != nil {
		t.Fatal(err)
	}
	if len(ws.events) == 0 || ws.events[0].Seq != st.EventCount {
		t.Fatalf("eventos: %+v", ws.events)
	}
	if l, _ := r.svc.ListRuns(context.Background(), &v1.ListRunsRequest{ActiveOnly: true}); len(l.Runs) != 0 {
		t.Fatalf("la terminada sigue como activa: %v", l)
	}
	if l, _ := r.svc.ListRuns(context.Background(), &v1.ListRunsRequest{}); len(l.Runs) != 1 {
		t.Fatalf("la terminada debe verse sin el filtro: %v", l)
	}
	if _, err := r.svc.GetAssistRun(context.Background(), &v1.GetAssistRunRequest{RunId: "nope"}); code(err) != codes.NotFound {
		t.Fatalf("err = %v", err)
	}
}

// Un puerto, una ejecución a la vez; otro puerto del mismo equipo sí.
func TestSecondRunOnSamePortIsRefused(t *testing.T) {
	const gi2 = "GigabitEthernet1/0/2"
	r := newRig(t, simulator.Config{Interfaces: map[string][]string{gi1: {"switchport mode access"}, gi2: {"switchport mode access"}}})
	p1, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	p2, err := r.plan(&v1.PlanPortsRequest{Vlan: 30})
	if err != nil {
		t.Fatal(err)
	}
	p3, _ := r.plan(&v1.PlanPortsRequest{Vlan: 30, Interfaces: []string{gi2}})
	run := r.start(p1.PlanId)
	r.waitState(run, "waiting-confirm")
	_, err = r.svc.StartRun(context.Background(), &v1.StartRunRequest{PlanId: p2.PlanId, Assisted: true})
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), run) {
		t.Fatalf("err = %v", err)
	}
	if len(r.d.V.Windows()) != 1 {
		t.Fatalf("la ejecución rechazada dejó una ventana abierta: %+v", r.d.V.Windows())
	}
	run3 := r.start(p3.PlanId)
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run3})
	r.waitDone(run3)
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitDone(run)
	// Liberado el puerto, el plan rechazado (sigue guardado) arranca.
	run2 := r.start(p2.PlanId)
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run2})
	r.waitDone(run2)
}

func TestPrunePlansRemovesOldestNotRandom(t *testing.T) {
	r := newRig(t, simulator.Config{})
	now := time.Now()
	for i := 0; i < maxKeptPlans; i++ {
		r.svc.plans[fmt.Sprint(i)] = &planRec{created: now.Add(-time.Duration(i) * time.Second)}
	}
	r.svc.prunePlansLocked(now)
	if _, ok := r.svc.plans[fmt.Sprint(maxKeptPlans-1)]; ok {
		t.Fatal("el plan más viejo sigue")
	}
	if len(r.svc.plans) != maxKeptPlans-1 {
		t.Fatalf("quedan %d", len(r.svc.plans))
	}
	for i := 0; i < maxKeptPlans-1; i++ {
		if _, ok := r.svc.plans[fmt.Sprint(i)]; !ok {
			t.Fatalf("se borró el plan %d, que no era el más viejo", i)
		}
	}
}

func TestPruneRunsDropsOldFinishedAndCapsTheRest(t *testing.T) {
	r := newRig(t, simulator.Config{})
	now := time.Now()
	defer func() { r.svc.runs = map[string]*runRec{} }() // los registros de mentira no tienen ejecución que esperar al cerrar
	r.svc.runs["viva"] = &runRec{}
	r.svc.runs["vieja"] = &runRec{ended: now.Add(-2 * runTTL)}
	for i := 0; i < maxKeptRuns+3; i++ {
		r.svc.runs[fmt.Sprint(i)] = &runRec{ended: now.Add(-time.Duration(i) * time.Second)}
	}
	r.svc.pruneRunsLocked(now)
	if _, ok := r.svc.runs["viva"]; !ok {
		t.Fatal("se borró una viva")
	}
	if _, ok := r.svc.runs["vieja"]; ok {
		t.Fatal("una terminada hace mucho sigue")
	}
	if n := len(r.svc.runs); n != maxKeptRuns+1 {
		t.Fatalf("quedan %d", n)
	}
	if _, ok := r.svc.runs[fmt.Sprint(maxKeptRuns+2)]; ok {
		t.Fatal("la más vieja sigue")
	}
}

func TestPortKeysTreatsEquivalentNamesAsOnePort(t *testing.T) {
	mk := func(n string) *planRec {
		return &planRec{t: target{host: "10.0.0.1", port: 22}, plan: assist.Plan{Devices: []assist.DevicePlan{{Apply: []string{"interface " + n, "shutdown"}}}}}
	}
	a, b := portKeys(mk("GigabitEthernet1/0/1")), portKeys(mk("gi1/0/1"))
	if len(a) != 1 || !reflect.DeepEqual(a, b) {
		t.Fatalf("%v %v", a, b)
	}
}
