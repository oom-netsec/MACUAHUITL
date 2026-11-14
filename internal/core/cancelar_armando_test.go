package core

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// cancelaAlTomar cancela el trabajo justo cuando ArmJob toma el inhibidor: el estado es "arming".
type cancelaAlTomar struct {
	*fakeInhibitor
	cancel func()
}

func (c cancelaAlTomar) Take(s string) (func(), []string) {
	c.cancel()
	return c.fakeInhibitor.Take(s)
}

// Cancelar mientras se arma debe impedir que el trabajo quede armado.
func TestCancelarDuranteElArmadoCancelaElTrabajo(t *testing.T) {
	var h *harness
	var job string
	inh := &fakeInhibitor{}
	h = newHarness(t, func(o *Options) {
		o.Inhibitor = cancelaAlTomar{inh, func() {
			if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job}); err != nil {
				t.Error(err)
			}
		}}
	})
	cred := h.ready(t)
	var fp string
	job, fp = h.created(t, cred, nil)
	_, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ArmJob = %v", err)
	}
	if st := h.summary(t, job).State; st != "cancelled" {
		t.Fatalf("state = %s", st)
	}
	if a, r := inh.counts(); a != r {
		t.Errorf("inhibidor sin liberar: %d tomados, %d liberados", a, r)
	}
	if rr, err := h.patrol.GetRun(ctx(t), &v1.GetRunRequest{JobId: job, Round: 1}); err != nil || rr.OutputPath != "" {
		t.Errorf("el trabajo cancelado apunta a una carpeta borrada: %v %v", rr.GetOutputPath(), err)
	}
	if d := h.summary(t, job).OutputDir; d != h.out {
		t.Errorf("OutputDir = %s, quería la raíz %s", d, h.out)
	}
	if ents, _ := os.ReadDir(h.out); len(ents) != 0 {
		t.Errorf("quedó la carpeta vacía de la corrida: %v", ents)
	}
	if a := h.auditText(t); strings.Contains(a, `"action":"job.arm"`) {
		t.Errorf("auditó un armado que no ocurrió: %s", a)
	}
}

// Si el armado falla con una cancelación pendiente, el trabajo queda cancelado (no vuelve a «created») y con su fase.
func TestArmadoFallidoConCancelacionPendienteQuedaCancelado(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	cj, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: h.spec(cred)})
	if err != nil {
		t.Fatal(err)
	}
	j, _ := h.core.getJob(cj.JobId)
	h.core.mu.Lock()
	j.cancelReq = true // lo que dejaría un CancelJob llegado durante el armado
	h.core.mu.Unlock()
	// Sin la huella aceptada el Login Test falla: el armado cae en fail().
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: cj.JobId}); err == nil {
		t.Fatal("el armado debía fallar")
	}
	s := h.summary(t, cj.JobId)
	if s.State != "cancelled" || s.Phases[len(s.Phases)-1].Kind != v1.JobPhaseKind_JOB_PHASE_KIND_CANCELLED {
		t.Fatalf("estado %s fases %v", s.State, phaseLines(s.Phases))
	}
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: cj.JobId}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("un trabajo cancelado se armó: %v", err)
	}
}

// duermeAlTomar simula una suspensión justo después de que Arm abrió la ventana y antes de quedar "armed".
type duermeAlTomar struct {
	*fakeInhibitor
	sleep func()
}

func (d duermeAlTomar) Take(s string) (func(), []string) {
	d.sleep()
	return d.fakeInhibitor.Take(s)
}

// Una suspensión durante el armado deja el trabajo pausado, no armado con la bóveda cerrada.
func TestSuspensionDuranteElArmadoDejaElTrabajoPausado(t *testing.T) {
	var h *harness
	h = newHarness(t, func(o *Options) {
		o.Inhibitor = duermeAlTomar{&fakeInhibitor{}, func() { h.core.OnSleep() }}
	})
	cred := h.ready(t)
	job, fp := h.created(t, cred, nil)
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeyFingerprints: []string{fp}}); err != nil {
		t.Fatal(err)
	}
	j, _ := h.core.getJob(job)
	h.core.mu.Lock()
	st, paused := j.state, j.paused
	h.core.mu.Unlock()
	if st != "armed" || !paused {
		t.Fatalf("state=%s paused=%v, quería armed y pausado", st, paused)
	}
}
