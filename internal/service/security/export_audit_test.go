package security

import (
	"context"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/pki"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// La auditoría de pki.export registra la ruta donde el cliente escribirá el archivo.
func TestPkiExportAuditaLaRuta(t *testing.T) {
	d := servicetest.New(t)
	s := &securitySvc{d: d}
	now := time.Now()
	k, err := pki.GenerateKey("p256")
	if err != nil {
		t.Fatal(err)
	}
	ca, err := pki.InitCA(k, "lab", 30, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PkiExport(context.Background(), &v1.PkiExportRequest{Format: "der", CertPem: string(ca), DestPath: "/tmp/x/ca.der"}); err != nil {
		t.Fatal(err)
	}
	if txt := d.AuditText(); !strings.Contains(txt, `dest=\"/tmp/x/ca.der\"`) {
		t.Fatalf("la auditoría no trae la ruta:\n%s", txt)
	}
}
