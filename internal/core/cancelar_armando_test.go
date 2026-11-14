package core

import (
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
	if a := h.auditText(t); strings.Contains(a, `"action":"job.arm"`) {
		t.Errorf("auditó un armado que no ocurrió: %s", a)
	}
}
