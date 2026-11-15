package assist

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// abortedChanged deja el puerto cambiado a la VLAN 20 y aborta en el paso de cierre: la ejecución termina aborted con SW1 cambiado.
func (r *rig) abortedChanged() (run string, plan *v1.PlanPortsResponse) {
	r.t.Helper()
	plan, err := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	if err != nil {
		r.t.Fatal(err)
	}
	run = r.start(plan.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	if s := r.waitState(run, "waiting-confirm"); s.Pending.GetKind() != "close" {
		r.t.Fatalf("se esperaba el cierre: %+v", s.Pending)
	}
	if _, err := r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run}); err != nil {
		r.t.Fatal(err)
	}
	r.waitState(run, "aborted")
	r.waitDone(run)
	return run, plan
}

func (r *rig) pending() []*v1.PendingRollback {
	r.t.Helper()
	l, err := r.svc.ListPendingRollbacks(context.Background(), &v1.ListPendingRollbacksRequest{})
	if err != nil {
		r.t.Fatal(err)
	}
	return l.Rollbacks
}

func (r *rig) startPending(run string, age bool) (string, error) {
	res, err := r.svc.StartPendingRollback(context.Background(), &v1.StartPendingRollbackRequest{RunId: run, AcceptAge: age, Assisted: true})
	if err != nil {
		return "", err
	}
	return res.RunId, nil
}

// confirmAll confirma cada paso hasta el estado final.
func (r *rig) confirmAll(run, final string) {
	r.t.Helper()
	for i := 0; i < 5; i++ {
		s := r.waitState(run, "waiting-confirm")
		r.confirm(run, s.Pending.Id)
		if s.Pending.Kind == "close" {
			break
		}
	}
	r.waitState(run, final)
	r.waitDone(run)
}

func (r *rig) samePlan(want *v1.PlanPortsResponse) {
	r.t.Helper()
	again, err := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	if err != nil || !reflect.DeepEqual(again.Plan.Devices[0].Rollback, want.Plan.Devices[0].Rollback) {
		r.t.Fatalf("el equipo no volvió a como estaba: %v %v", err, again)
	}
}

func TestAbortedRunLeavesPendingRollbackThatRestoresTheDevice(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, plan := r.abortedChanged()
	p := r.pending()
	if len(p) != 1 || p[0].RunId != run || p[0].Kind != "ports" || p[0].Devices[0].Device != "SW1" ||
		!reflect.DeepEqual(p[0].Devices[0].RollbackLines, plan.Plan.Devices[0].Rollback) {
		t.Fatalf("pendientes = %+v", p)
	}
	nrun, err := r.startPending(run, false)
	if err != nil {
		t.Fatal(err)
	}
	if s := r.waitState(nrun, "waiting-confirm"); !reflect.DeepEqual(s.Pending.Lines, plan.Plan.Devices[0].Rollback) {
		t.Fatalf("el primer paso debe ser la reversa original: %+v", s.Pending)
	}
	r.confirmAll(nrun, "done")
	if len(r.pending()) != 0 {
		t.Fatal("terminó bien: la entrada reservada debía borrarse")
	}
	r.samePlan(plan)
	if txt := r.d.AuditText(); !strings.Contains(txt, "assist.pending_rollback.start") || !strings.Contains(txt, "assist.pending_rollback.end") {
		t.Fatalf("falta la auditoría:\n%s", txt)
	}
	if _, err := r.startPending(run, false); code(err) != codes.NotFound {
		t.Fatalf("ya borrada: %v", err)
	}
}

// El equipo cambió por otro lado después de la ejecución: el pre-check no coincide y no se manda ninguna línea.
func TestPendingRollbackStopsWhenSomeoneElseChangedTheDevice(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, _ := r.abortedChanged()
	other, _ := r.plan(&v1.PlanPortsRequest{Vlan: 30})
	o := r.start(other.PlanId)
	r.waitState(o, "waiting-confirm")
	r.confirm(o, "apply-1")
	r.closeAndWait(o)
	r.waitDone(o)
	before := len(r.rec.Lines())
	nrun, err := r.startPending(run, false)
	if err != nil {
		t.Fatal(err)
	}
	// Debe detenerse en el pre-check, sin llegar a pedir confirmación de ningún paso.
	s := r.waitState(nrun, "failed")
	if s.Pending != nil || len(s.Changed) != 0 || !strings.Contains(s.FailReason, "cambió") {
		t.Fatalf("estado %+v", s)
	}
	r.waitDone(nrun)
	for _, l := range r.rec.Lines()[before:] {
		if strings.HasPrefix(l, "switchport") || strings.HasPrefix(l, "interface") {
			t.Fatalf("se mandó configuración tras el cambio ajeno: %q", r.rec.Lines()[before:])
		}
	}
	if len(r.pending()) != 1 {
		t.Fatal("la reversa debe conservarse si no se aplicó")
	}
}

func TestPendingRollbackSurvivesCoreRestart(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, plan := r.abortedChanged()
	r.svc.Close()
	r.svc = newSvc(r.d) // núcleo nuevo, misma bóveda
	t.Cleanup(r.svc.Close)
	if p := r.pending(); len(p) != 1 || p[0].RunId != run {
		t.Fatalf("pendientes tras reiniciar: %+v", p)
	}
	nrun, err := r.startPending(run, false)
	if err != nil {
		t.Fatal(err)
	}
	r.confirmAll(nrun, "done")
	r.samePlan(plan)
}

func TestPendingRollbackOlderThanADayNeedsAcceptAge(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, _ := r.abortedChanged()
	r.d.SetClock(func() time.Time { return time.Now().Add(25 * time.Hour) })
	if p := r.pending(); p[0].AgeSeconds < 25*3600 {
		t.Fatalf("antigüedad %d", p[0].AgeSeconds)
	}
	_, err := r.startPending(run, false)
	if code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "25h") || !strings.Contains(err.Error(), "--accept-age") {
		t.Fatalf("sin accept_age: %v", err)
	}
	nrun, err := r.startPending(run, true)
	if err != nil {
		t.Fatal(err)
	}
	r.confirmAll(nrun, "done")
}

func TestAbortedCredRotateLeavesNoPendingRollback(t *testing.T) {
	r := newRotRig(t, simulator.Config{})
	res, err := r.rotate(&v1.PlanCredRotateRequest{User: "tech", NewSecret: newSec, UpdateCredentialId: r.tech})
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm") // save-1
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitState(run, "failed")
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run}) // no revierte: queda failed con el equipo cambiado
	r.waitDone(run)
	if st := r.state(run); len(st.Changed) != 1 {
		t.Fatalf("el equipo debía seguir cambiado: %+v", st)
	}
	if len(r.pending()) != 0 {
		t.Fatal("la reversa de cred rotate toca la bóveda: no se guarda")
	}
}

func TestPendingRollbackNotSavedWhenVaultIsLocked(t *testing.T) {
	r := newRig(t, simulator.Config{})
	plan, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	run := r.start(plan.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm")
	r.d.V.LockAll()
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitState(run, "aborted")
	r.waitDone(run)
	if txt := r.d.AuditText(); !strings.Contains(txt, "assist.pending_rollback.save_failed") {
		t.Fatalf("debía auditar que no se pudo guardar:\n%s", txt)
	}
}

// ---- revisión de seguridad ----

func (r *rig) pendingLabels() (n int) {
	r.t.Helper()
	all, err := r.d.V.ListAll()
	if err != nil {
		r.t.Fatal(err)
	}
	for _, i := range all {
		if strings.HasPrefix(i.Label, pendingPrefix) {
			n++
		}
	}
	return n
}

// startAt deja un puerto cambiado y la ejecución esperando el paso de cierre.
func (r *rig) changedAtClose() string {
	r.t.Helper()
	plan, err := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	if err != nil {
		r.t.Fatal(err)
	}
	run := r.start(plan.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm")
	return run
}

// Mientras la ejecución vive la reversa ya está guardada (una caída no la pierde), no se ofrece en este núcleo y un núcleo nuevo sobre la
// misma bóveda la ve.
func TestPendingRollbackIsSavedWhileTheRunIsAliveAndSurvivesACrash(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run := r.changedAtClose()
	if r.pendingLabels() != 1 {
		t.Fatal("al pasar a cambiado debía quedar guardada")
	}
	if len(r.pending()) != 0 {
		t.Fatal("con la ejecución viva en este núcleo no se ofrece")
	}
	if _, err := r.startPending(run, false); code(err) != codes.FailedPrecondition {
		t.Fatalf("iniciar la reversa de una ejecución viva: %v", err)
	}
	if _, err := r.svc.DiscardPendingRollback(context.Background(), &v1.DiscardPendingRollbackRequest{RunId: run}); code(err) != codes.FailedPrecondition {
		t.Fatalf("descartar una ejecución viva: %v", err)
	}
	crashed := newSvc(r.d) // el núcleo cayó sin dejar estado terminal: otro servicio sobre la misma bóveda
	t.Cleanup(crashed.Close)
	l, err := crashed.ListPendingRollbacks(context.Background(), &v1.ListPendingRollbacksRequest{})
	if err != nil || len(l.Rollbacks) != 1 || l.Rollbacks[0].RunId != run {
		t.Fatalf("%v %+v", err, l)
	}
}

// El ingeniero dejó el cambio a propósito (confirmó el cierre) o la ejecución se revirtió sola: nunca queda candidata.
func TestDoneAndRolledBackRunsAreNeverPendingCandidates(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run := r.changedAtClose()
	r.confirm(run, "close")
	r.waitState(run, "done")
	r.waitDone(run)
	if r.pendingLabels() != 0 || len(r.pending()) != 0 {
		t.Fatal("una ejecución cerrada con «dejarlo» no es candidata")
	}
	plan, _ := r.plan(&v1.PlanPortsRequest{Vlan: 30})
	run = r.start(plan.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm")
	if r.pendingLabels() != 1 {
		t.Fatal("cambiado: guardada")
	}
	if _, err := r.svc.Rollback(context.Background(), &v1.RollbackRequest{RunId: run}); err != nil {
		t.Fatal(err)
	}
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "rollback-1")
	r.waitState(run, "rolled-back")
	r.waitDone(run)
	if r.pendingLabels() != 0 {
		t.Fatal("revertida por la propia ejecución: no queda nada")
	}
}

func TestFailedAndAbandonedRunsLeavePendingRollbacks(t *testing.T) {
	r := newRig(t, simulator.Config{ConfigErrors: map[string]string{"description Telefono": "% Invalid input detected at '^' marker."}})
	plan, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20, Description: ptr("Telefono"), Shutdown: ptr(false)})
	run := r.start(plan.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "failed")
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitDone(run)
	if p := r.pending(); len(p) != 1 || p[0].RunId != run {
		t.Fatalf("failed: %+v", p)
	}
	nrun, err := r.startPending(run, false)
	if err != nil {
		t.Fatal(err)
	}
	r.confirmAll(nrun, "done")
	if len(r.pending()) != 0 {
		t.Fatal("aplicada: se borra")
	}

	r2 := newRig(t, simulator.Config{})
	r2.svc.decisionTimeout = 200 * time.Millisecond
	run2 := r2.changedAtClose()
	r2.waitState(run2, "abandoned")
	r2.waitDone(run2)
	p := r2.pending()
	if len(p) != 1 || p[0].RunId != run2 {
		t.Fatalf("abandoned: %+v", p)
	}
	r2.svc.decisionTimeout = 0
	nrun, err = r2.startPending(run2, false)
	if err != nil {
		t.Fatal(err)
	}
	r2.confirmAll(nrun, "done")
}

// El equipo no responde en el pre-check: failed sin cambiar nada y la reversa se conserva.
func TestPendingRollbackWithUnreachableDeviceFailsAndIsKept(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, _ := r.abortedChanged()
	rec, err := r.svc.loadPending(pendingPrefix + run)
	if err != nil {
		t.Fatal(err)
	}
	rec.Port = 1 // nadie escucha
	if err := r.svc.savePending(rec); err != nil {
		t.Fatal(err)
	}
	nrun, err := r.startPending(run, false)
	if err != nil {
		t.Fatal(err)
	}
	s := r.waitState(nrun, "failed")
	if len(s.Changed) != 0 || s.Pending != nil {
		t.Fatalf("%+v", s)
	}
	r.waitDone(nrun)
	if len(r.pending()) != 1 {
		t.Fatal("se conserva")
	}
}

func TestPendingRollbackSecretsNeverLeak(t *testing.T) {
	const comm = "Zx9-Secreta.Comm"
	r := newRig(t, simulator.Config{Running: "hostname SW1\nsnmp-server community otra RO\n!\nend\n"})
	res, err := r.snippet(tplReq("snmp-community", map[string]string{"community": comm}))
	if err != nil {
		t.Fatal(err)
	}
	run := r.start(res.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm")
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitState(run, "aborted")
	r.waitDone(run)
	p := r.pending()
	if len(p) != 1 || strings.Contains(fmt.Sprint(p), comm) {
		t.Fatalf("la lista cita la community: %v", p)
	}
	nrun, err := r.startPending(run, false)
	if err != nil {
		t.Fatal(err)
	}
	r.confirmAll(nrun, "done")
	rec, _ := r.svc.get(context.Background(), nrun)
	evs, _ := rec.run.Events(0)
	if strings.Contains(fmt.Sprint(evs), comm) || strings.Contains(r.d.AuditText(), comm) {
		t.Fatal("la community salió en eventos o auditoría")
	}
	if got := strings.Join(r.rec.Lines(), "|"); !strings.Contains(got, "no snmp-server community "+comm) {
		t.Fatalf("el equipo no recibió la reversa: %s", got)
	}
}

func TestPendingRollbackCannotBeStartedTwiceAndAbortKeepsIt(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, _ := r.abortedChanged()
	n1, err := r.startPending(run, false)
	if err != nil {
		t.Fatal(err)
	}
	r.waitState(n1, "waiting-confirm")
	if _, err := r.startPending(run, false); code(err) != codes.FailedPrecondition {
		t.Fatalf("el segundo arranque debía rechazarse: %v", err)
	}
	r.confirm(n1, "apply-1")
	if s := r.waitState(n1, "waiting-confirm"); s.Pending.Kind != "close" {
		t.Fatalf("%+v", s.Pending)
	}
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: n1}) // abort en el cierre de la ejecución de reversa
	r.waitState(n1, "aborted")
	r.waitDone(n1)
	if len(r.pending()) != 1 || r.pendingLabels() != 1 {
		t.Fatal("una reversa que no terminó done conserva la entrada (y no guarda otra)")
	}
}

func TestStartPendingRollbackNeedsAssisted(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, _ := r.abortedChanged()
	_, err := r.svc.StartPendingRollback(context.Background(), &v1.StartPendingRollbackRequest{RunId: run})
	if code(err) != codes.FailedPrecondition {
		t.Fatalf("sin assisted: %v", err)
	}
}

func TestDiscardPendingRollbackAndUnreadableEntries(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, _ := r.abortedChanged()
	if err := r.d.V.PutReserved(vault.Credential{Label: pendingPrefix + "rota", Username: "x", Password: secret.New([]byte("{no es json"))}); err != nil {
		t.Fatal(err)
	}
	p := r.pending()
	if len(p) != 2 {
		t.Fatalf("la ilegible no debe tumbar la lista: %+v", p)
	}
	var bad *v1.PendingRollback
	for _, x := range p {
		if x.Unreadable {
			bad = x
		}
	}
	if bad == nil || bad.RunId != "rota" {
		t.Fatalf("falta la ilegible: %+v", p)
	}
	ctx := context.Background()
	for _, id := range []string{"rota", run} {
		if _, err := r.svc.DiscardPendingRollback(ctx, &v1.DiscardPendingRollbackRequest{RunId: id}); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.pending()) != 0 || r.pendingLabels() != 0 {
		t.Fatal("seguían ahí")
	}
	if _, err := r.svc.DiscardPendingRollback(ctx, &v1.DiscardPendingRollbackRequest{RunId: run}); code(err) != codes.NotFound {
		t.Fatalf("descartar dos veces: %v", err)
	}
	if !strings.Contains(r.d.AuditText(), "assist.pending_rollback.discard") {
		t.Fatal("falta la auditoría")
	}
}

func TestPendingRollbackWarnsAboutWriteMemory(t *testing.T) {
	r := newRig(t, simulator.Config{})
	plan, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20, WriteMemory: true})
	run := r.start(plan.PlanId)
	r.waitState(run, "waiting-confirm")
	r.confirm(run, "apply-1")
	r.waitState(run, "waiting-confirm") // save-1
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitState(run, "aborted")
	r.waitDone(run)
	if p := r.pending(); len(p) != 1 || !p[0].WriteMemory {
		t.Fatalf("%+v", p)
	}
}

// No se puede descartar mientras corre la ejecución de reversa de esa entrada.
func TestDiscardIsRefusedWhileItsRollbackRunIsAlive(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, _ := r.abortedChanged()
	nrun, err := r.startPending(run, false)
	if err != nil {
		t.Fatal(err)
	}
	r.waitState(nrun, "waiting-confirm")
	discard := &v1.DiscardPendingRollbackRequest{RunId: run}
	if _, err := r.svc.DiscardPendingRollback(context.Background(), discard); code(err) != codes.FailedPrecondition {
		t.Fatalf("descartar con la reversa en curso: %v", err)
	}
	r.confirmAll(nrun, "done")
}

// Un descarte en la ventana entre run.Done() y afterRun no se revierte: afterRun y Persist no la vuelven a guardar.
func TestDiscardedPendingRollbackIsNotSavedAgain(t *testing.T) {
	r := newRig(t, simulator.Config{})
	run, _ := r.abortedChanged()
	if _, err := r.svc.DiscardPendingRollback(context.Background(), &v1.DiscardPendingRollbackRequest{RunId: run}); err != nil {
		t.Fatal(err)
	}
	rr, _ := r.svc.get(context.Background(), run)
	pers := &persister{s: r.svc, runID: run, t: target{host: "x", port: 22, cred: "c"}}
	r.svc.afterRun(rr, pers, "") // lo que haría el hilo de la ejecución si el descarte llegó antes
	pers.sync(rr.run.Leftover())
	if r.pendingLabels() != 0 {
		t.Fatal("el descarte se revirtió")
	}
}

// Con la bóveda cerrada el fallo de guardado se audita una sola vez por ejecución, no en cada sync.
func TestSaveFailedIsAuditedOncePerRun(t *testing.T) {
	r := newRig(t, simulator.Config{})
	plan, _ := r.plan(&v1.PlanPortsRequest{Vlan: 20})
	run := r.start(plan.PlanId)
	r.waitState(run, "waiting-confirm")
	r.d.V.LockAll()
	r.confirm(run, "apply-1") // cambiado, estado releído y fin: tres intentos de guardar
	r.waitState(run, "waiting-confirm")
	r.svc.Abort(context.Background(), &v1.AbortRequest{RunId: run})
	r.waitState(run, "aborted")
	r.waitDone(run)
	if n := strings.Count(r.d.AuditText(), "assist.pending_rollback.save_failed"); n != 1 {
		t.Fatalf("save_failed auditado %d veces", n)
	}
}
