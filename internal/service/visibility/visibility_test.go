package visibility

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/snmp"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/snmp/snmptest"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// Revisión: gosnmp marca por su cuenta; el único freno es Target.Control. Sin
// autorización para la ejecución, la consulta no sale y queda egress.denied.
func TestVisibilitySnmpSinAllowNoSale(t *testing.T) {
	d := servicetest.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	a := snmptest.New(t, "lab-ro", nil)
	id, err := d.CreateVault().Put(vault.Credential{Label: "snmp", Username: "snmp", Password: secret.New([]byte("lab-ro")), Enable: secret.New(nil), SSHKey: secret.New(nil)})
	if err != nil {
		t.Fatal(err)
	}
	s := &visibilitySvc{d: d}
	run := service.RunID("snmp")
	tg, err := s.snmpTarget(ctx, &v1.SnmpTarget{Host: "127.0.0.1", Port: uint32(a.Port()), Version: "2c", CredentialId: id, TimeoutMs: 300}, run)
	if err != nil {
		t.Fatal(err)
	}
	d.Guard().Revoke(run)
	if _, err := snmp.Get(ctx, tg, []string{"1.3.6.1.2.1.1.5.0"}); !errors.Is(err, transport.ErrEgressDenied) {
		t.Fatalf("err = %v", err)
	}
	if a.Requests() != 0 {
		t.Fatal("el agente recibió la consulta")
	}
	if txt := d.AuditText(); !strings.Contains(txt, `"action":"egress.denied"`) || !strings.Contains(txt, run) {
		t.Fatalf("auditoría:\n%s", txt)
	}
}
