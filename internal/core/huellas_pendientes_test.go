package core

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

// Pedido de Front: el armado fallido de ad hoc y respaldos dice su motivo y las huellas pendientes por equipo, con
// host en la forma que espera accepted_host_keys; la UI arma «Confiar y reintentar» sin correr el Login Test.
func TestArmadoFallidoTraeHuellasPendientes(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	host := transport.HostKeyID(h.target.Address, uint16(h.target.Port))
	r, err := v1.NewAdhocServiceClient(h.conn).StartAdhoc(ctx(t), &v1.StartAdhocRequest{Targets: []*v1.Target{h.target}, CredentialId: cred, Commands: "show clock\n"})
	if err != nil || r.Armed || r.JobId == "" || r.Reason != "patrol.svc.login_failed" || len(r.HostKeys) != 1 {
		t.Fatalf("adhoc = %+v %v", r, err)
	}
	k := r.HostKeys[0]
	if k.Host != host || !strings.HasPrefix(k.Fingerprint, "SHA256:") || k.KeyType == "" || k.Changed {
		t.Fatalf("huella pendiente = %+v, host esperado %s", k, host)
	}
	// Rearmar el mismo ad hoc con ArmJob: si vuelve a fallar, el ErrorInfo trae la misma lista (metadata host_keys).
	_, err = h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: r.JobId, AcceptedHostKeys: []*v1.AcceptedHostKey{{Host: host, Fingerprint: "SHA256:otra"}}})
	reason, meta := reasonOf(err)
	if status.Code(err) != codes.FailedPrecondition || reason != "patrol.svc.login_failed" || !strings.Contains(meta["host_keys"], k.Fingerprint) {
		t.Fatalf("rearmado = %v %q %v", err, reason, meta)
	}
	if _, keys := service.ArmFailure(err); len(keys) != 1 || keys[0].Host != host || keys[0].Fingerprint != k.Fingerprint || keys[0].KeyType != k.KeyType {
		t.Fatalf("metadata host_keys = %q -> %v", meta["host_keys"], keys)
	}
	// La fase ARM_FAILED del trabajo no guarda la lista JSON (solo viaja en el error).
	if s := h.summary(t, r.JobId); strings.Contains(fmt.Sprint(s.Phases), "host_keys") {
		t.Errorf("la fase guarda host_keys: %v", s.Phases)
	}
	if _, err := h.patrol.ArmJob(ctx(t), &v1.ArmJobRequest{JobId: r.JobId, AcceptedHostKeys: []*v1.AcceptedHostKey{{Host: k.Host, Fingerprint: k.Fingerprint}}}); err != nil {
		t.Fatalf("con la huella pendiente aceptada: %v", err)
	}
}

// Respaldos: el primer intento devuelve la huella pendiente; el rearmado con job_id usa el mismo trabajo (no crea otro)
// y lo recoge al terminar.
func TestRespaldoRearmaElMismoTrabajo(t *testing.T) {
	h := newHarness(t, nil)
	cred := h.ready(t)
	bc := v1.NewBackupServiceClient(h.conn)
	r, err := bc.StartBackup(ctx(t), &v1.StartBackupRequest{Targets: []*v1.Target{h.target}, CredentialId: cred})
	if err != nil || r.Armed || r.Reason != "patrol.svc.login_failed" || len(r.HostKeys) != 1 {
		t.Fatalf("start = %+v %v", r, err)
	}
	k := r.HostKeys[0]
	// Otra huella: sigue sin armar, con la misma forma de respuesta.
	r2, err := bc.StartBackup(ctx(t), &v1.StartBackupRequest{JobId: r.JobId, AcceptedHostKeys: []*v1.AcceptedHostKey{{Host: k.Host, Fingerprint: "SHA256:otra"}}})
	if err != nil || r2.Armed || r2.JobId != r.JobId || len(r2.HostKeys) != 1 {
		t.Fatalf("rearmado fallido = %+v %v", r2, err)
	}
	r3, err := bc.StartBackup(ctx(t), &v1.StartBackupRequest{JobId: r.JobId, AcceptedHostKeys: []*v1.AcceptedHostKey{{Host: k.Host, Fingerprint: k.Fingerprint}}})
	if err != nil || !r3.Armed || r3.JobId != r.JobId {
		t.Fatalf("rearmado = %+v %v", r3, err)
	}
	if l, _ := h.patrol.ListJobs(ctx(t), &v1.ListJobsRequest{}); len(l.Jobs) != 1 {
		t.Fatalf("creó otro trabajo: %v", l.Jobs)
	}
	// Revisión: otro «Confiar y reintentar» sobre el respaldo ya armado no es un armado fallido: vuelve el error.
	if r4, err := bc.StartBackup(ctx(t), &v1.StartBackupRequest{JobId: r.JobId, AcceptedHostKeys: []*v1.AcceptedHostKey{{Host: k.Host, Fingerprint: k.Fingerprint}}}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rearmado de un armado = %+v %v", r4, err)
	}
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		res, err := bc.CollectBackups(ctx(t), &v1.CollectBackupsRequest{JobId: r.JobId})
		if err != nil {
			t.Fatal(err)
		}
		if res.Done {
			if res.Error != "" || !strings.Contains(res.Report.GetJson(), `"saved":["`) {
				t.Fatalf("res = %+v", res)
			}
			return
		}
	}
	t.Fatal("el respaldo rearmado no terminó")
}

// job_id solo rearma un respaldo propio que quedó sin armar.
func TestRespaldoJobIDAjeno(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	if _, err := v1.NewBackupServiceClient(h.conn).StartBackup(ctx(t), &v1.StartBackupRequest{JobId: "no-existe"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("err = %v", err)
	}
}
