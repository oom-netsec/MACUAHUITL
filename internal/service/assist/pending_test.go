package assist

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
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
	res, err := r.svc.StartPendingRollback(context.Background(), &v1.StartPendingRollbackRequest{RunId: run, AcceptAge: age})
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
