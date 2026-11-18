package core

import (
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// El campo nuevo ata la huella a un equipo: con otro host no arma; con el del trabajo sí.
func TestArmJobHuellaPorHost(t *testing.T) {
	h := newHarness(t, nil)
	job, fp := h.created(t, h.ready(t), nil)
	otro := &v1.ArmJobRequest{JobId: job, AcceptedHostKeys: []*v1.AcceptedHostKey{{Host: "10.9.9.9:22", Fingerprint: fp}}}
	if _, err := h.patrol.ArmJob(ctx(t), otro); err == nil {
		t.Fatal("la huella de otro host no debe armar")
	}
	hp := h.target.Address + ":" + strconv.Itoa(int(h.target.Port))
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: job, AcceptedHostKeys: []*v1.AcceptedHostKey{{Host: hp, Fingerprint: fp}}}); err != nil {
		t.Fatalf("campo nuevo: %v", err)
	}
	// Las huellas aceptadas no se guardan con el trabajo: no hay formato viejo que migrar al recargar.
	var spec string
	if err := h.core.db.QueryRow(`SELECT spec_json FROM jobs WHERE id=?`, job).Scan(&spec); err != nil || strings.Contains(spec, "SHA256:") || strings.Contains(strings.ToLower(spec), "accepted") {
		t.Fatalf("spec guardado = %q (%v)", spec, err)
	}
}

// El campo viejo con varios destinos no vale: InvalidArgument y el trabajo sigue en created.
func TestArmJobCampoViejoConVariosDestinosEsAmbiguo(t *testing.T) {
	h := newHarness(t, nil)
	s := h.spec(h.ready(t))
	s.Targets = append(s.Targets, &v1.Target{Address: "127.0.0.1", Port: 1})
	cj, err := h.patrol.CreateJob(ctx(t), &v1.CreateJobRequest{Spec: s})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: cj.JobId, AcceptedHostKeyFingerprints: []string{"SHA256:x"}})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "huella") {
		t.Fatalf("err = %v", err)
	}
	if st := h.summary(t, cj.JobId).State; st != "created" {
		t.Fatalf("estado = %s", st)
	}
}

// CaptureChange reenvía accepted_host_keys a ArmJob: con el host del trabajo arma; con otro host no.
func TestCaptureChangeHuellaPorHost(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	ch := v1.NewChangeServiceClient(h.conn)
	spec := &v1.JobSpec{Name: "cambio-hk", Targets: []*v1.Target{h.target}, DefaultCredentialId: cred, OutputDir: h.out,
		Schedule: &v1.Schedule{IntervalSeconds: 60, Rounds: 5}}
	cr, err := ch.CreateChange(ctx(t), &v1.CreateChangeRequest{Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	pre, err := ch.CaptureChange(ctx(t), &v1.CaptureChangeRequest{ChangeId: cr.ChangeId, Phase: v1.ChangePhase_CHANGE_PHASE_PRE})
	if err != nil || pre.Armed {
		t.Fatalf("sin huella = %+v %v", pre, err)
	}
	fp := h.loginTest(t, pre.JobId)[0].HostKeyFingerprint
	pre, err = ch.CaptureChange(ctx(t), &v1.CaptureChangeRequest{ChangeId: cr.ChangeId, Phase: v1.ChangePhase_CHANGE_PHASE_PRE,
		AcceptedHostKeys: []*v1.AcceptedHostKey{{Host: "10.9.9.9:22", Fingerprint: fp}}})
	if err != nil || pre.Armed {
		t.Fatalf("la huella de otro host no debe armar: %+v %v", pre, err)
	}
	pre, err = ch.CaptureChange(ctx(t), &v1.CaptureChangeRequest{ChangeId: cr.ChangeId, Phase: v1.ChangePhase_CHANGE_PHASE_PRE,
		AcceptedHostKeys: []*v1.AcceptedHostKey{{Host: h.target.Address + ":" + strconv.Itoa(int(h.target.Port)), Fingerprint: fp}}})
	if err != nil || !pre.Armed {
		t.Fatalf("campo nuevo = %+v %v", pre, err)
	}
}
