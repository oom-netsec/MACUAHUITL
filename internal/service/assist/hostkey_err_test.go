package assist

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// Los Plan* que abren sesión deben conservar el reason y la metadata de la llave de host (la UI los usa para
// «Confiar y reintentar»), no solo el texto del error.
func TestPlanHostKeyErrorConservaReasonYMetadata(t *testing.T) {
	ctx := context.Background()
	plans := func(r *rig) map[string]func() error {
		id := r.saveBackup("hostname SW1\n", false)
		return map[string]func() error{
			"PlanRestore": func() error {
				_, err := r.svc.PlanRestore(ctx, &v1.PlanRestoreRequest{Target: r.target, BackupId: id})
				return err
			},
			"PlanSnippet": func() error {
				req := vlanReq(30, "Cuarentena")
				req.Target = r.target
				_, err := r.svc.PlanSnippet(ctx, req)
				return err
			},
			"PlanPorts": func() error {
				_, err := r.svc.PlanPorts(ctx, &v1.PlanPortsRequest{Target: r.target, Interfaces: []string{gi1}, Vlan: 20})
				return err
			},
			"PlanCredRotate": func() error {
				_, err := r.svc.PlanCredRotate(ctx, &v1.PlanCredRotateRequest{Target: r.target, User: "tech", NewSecret: "un-secreto-largo-123"})
				return err
			},
		}
	}
	check := func(t *testing.T, name string, err error, reason string) {
		t.Helper()
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("%s: código = %v (%v)", name, status.Code(err), err)
		}
		var ei *errdetails.ErrorInfo
		for _, d := range status.Convert(err).Details() {
			if x, ok := d.(*errdetails.ErrorInfo); ok {
				ei = x
			}
		}
		if ei == nil || ei.Reason != reason {
			t.Fatalf("%s: ErrorInfo = %v, quiero reason %s", name, ei, reason)
		}
		for _, k := range []string{"host", "fingerprint", "key_type"} {
			if ei.Metadata[k] == "" {
				t.Fatalf("%s: falta metadata %q: %v", name, k, ei.Metadata)
			}
		}
	}
	r := newRig(t, simulator.Config{})
	for name, f := range plans(r) {
		check(t, name+" desconocida", f(), "transport.hostkey.unknown")
	}
	// Llave cambiada: el equipo ya estaba registrado con otra llave.
	r = newRig(t, simulator.Config{})
	_, other := simulator.Start(t, simulator.Config{Hostname: "OTRO"}) // otra llave de host
	if err := r.d.H.Add(fmt.Sprintf("%s:%d", r.target.Address, r.target.Port), other); err != nil {
		t.Fatal(err)
	}
	for name, f := range plans(r) {
		check(t, name+" cambiada", f(), "transport.hostkey.changed")
	}
}
