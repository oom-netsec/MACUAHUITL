package core

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"software.sslmate.com/src/go-pkcs12"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/radiustest"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/tacacstest"
)

func split(t *testing.T, addr string) (string, uint32) {
	ap := netip.MustParseAddrPort(addr)
	return ap.Addr().String(), uint32(ap.Port())
}

// El secreto compartido y el usuario de prueba salen de la bóveda; nada de eso
// llega a la auditoría ni al reporte.
func TestRadiusFromVaultNoSecretLeak(t *testing.T) {
	h := newHarness(t, nil)
	h.ready(t)
	sec, _ := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "radius", Username: "-", Password: []byte("MARKER-SECRET")})
	user, _ := h.vault.PutCredential(ctx(t), &v1.PutCredentialRequest{Label: "prueba", Username: "alice", Password: []byte("MARKER-USERPW")})
	f, err := radiustest.StartFake(radiustest.FakeConfig{Secret: "MARKER-SECRET", Users: map[string]string{"alice": "MARKER-USERPW"}, Reply: radiustest.AuthzReply()})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	host, port := split(t, f.Addr())
	sc := v1.NewSecurityServiceClient(h.conn)
	r, err := sc.RadiusTest(ctx(t), &v1.RadiusTestRequest{Host: host, AuthPort: port, AcctPort: port, Accounting: true,
		SharedSecret: &v1.SecretSource{CredentialId: sec.Id}, Password: &v1.SecretSource{CredentialId: user.Id}, NasPortType: "ethernet", TimeoutMs: 500})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Report.Text, "Access-Accept") || !json.Valid([]byte(r.Report.Json)) {
		t.Fatal(r.Report.Text)
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `"action":"security.radius"`) || strings.Contains(txt, "MARKER-SECRET") || strings.Contains(txt, "MARKER-USERPW") {
		t.Fatalf("auditoría:\n%s", txt)
	}
	if strings.Contains(r.Report.Json+r.Report.Text, "MARKER") {
		t.Fatal("secreto en el reporte")
	}
	// Con la bóveda cerrada no hay secretos de la bóveda.
	h.vault.Lock(ctx(t), &v1.LockRequest{})
	_, err = sc.RadiusTest(ctx(t), &v1.RadiusTestRequest{Host: host, AuthPort: port, SharedSecret: &v1.SecretSource{CredentialId: sec.Id}, Username: "alice", Password: &v1.SecretSource{Value: []byte("x")}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("bóveda cerrada: %v", err)
	}
}

func TestRadiusValidationAndTypedSecret(t *testing.T) {
	h := newHarness(t, nil)
	sc := v1.NewSecurityServiceClient(h.conn)
	if _, err := sc.RadiusTest(ctx(t), &v1.RadiusTestRequest{Host: "127.0.0.1", Username: "a"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("sin secreto: %v", err)
	}
	// Puerto cerrado: el reporte dice que no hubo respuesta; no es error del RPC.
	r, err := sc.RadiusTest(ctx(t), &v1.RadiusTestRequest{Host: "127.0.0.1", AuthPort: 9, Username: "a",
		SharedSecret: &v1.SecretSource{Value: []byte("s")}, Password: &v1.SecretSource{Value: []byte("p")}, TimeoutMs: 100})
	if err != nil || !strings.Contains(r.Report.Text, "sin respuesta") {
		t.Fatalf("%v %v", r, err)
	}
}

func TestTacacsTest(t *testing.T) {
	h := newHarness(t, nil)
	f, err := tacacstest.StartFake(tacacstest.FakeConfig{Secret: "MARKER-TAC", Users: map[string]string{"admin": "MARKER-PW2"}, Permit: map[string][]string{"show": {"priv-lvl=15"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	host, port := split(t, f.Addr())
	r, err := v1.NewSecurityServiceClient(h.conn).TacacsTest(ctx(t), &v1.TacacsTestRequest{Host: host, Port: port, Username: "admin",
		SharedSecret: &v1.SecretSource{Value: []byte("MARKER-TAC")}, Password: &v1.SecretSource{Value: []byte("MARKER-PW2")}, Command: "show running-config", Accounting: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Report.Text, "PASS_ADD") || !strings.Contains(r.Report.Text, "priv-lvl=15") {
		t.Fatal(r.Report.Text)
	}
	txt := h.auditText(t)
	if !strings.Contains(txt, `"action":"security.tacacs"`) || strings.Contains(txt, "MARKER") {
		t.Fatalf("auditoría:\n%s", txt)
	}
}

func TestPkiFlow(t *testing.T) {
	h := newHarness(t, nil)
	sc := v1.NewSecurityServiceClient(h.conn)
	ca, err := sc.PkiCaInit(ctx(t), &v1.PkiCaInitRequest{Name: "Lab CA", KeyPassword: []byte("MARKER-CAPW")})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ca.Report.Text, "LABORATORIO") || !strings.Contains(ca.SealedKeyPem, "SEALED PRIVATE KEY") {
		t.Fatal(ca.Report.Text)
	}
	csr, err := sc.PkiCsr(ctx(t), &v1.PkiCsrRequest{Algorithm: "p256", KeyPassword: []byte("MARKER-KPW"),
		Subject: &v1.PkiSubject{Cn: "ise01.lab"}, Dns: []string{"ise01.lab"}, Ips: []string{"10.0.0.10"}})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := sc.PkiCaSign(ctx(t), &v1.PkiCaSignRequest{CaCertPem: ca.CaCertPem, CaSealedKeyPem: ca.SealedKeyPem, CaKeyPassword: []byte("MARKER-CAPW"), CsrPem: csr.CsrPem, Profile: "server"})
	if err != nil || !strings.Contains(cert.Report.Text, "serverAuth") {
		t.Fatalf("%v %v", cert, err)
	}
	if _, err := sc.PkiCaSign(ctx(t), &v1.PkiCaSignRequest{CaCertPem: ca.CaCertPem, CaSealedKeyPem: ca.SealedKeyPem, CaKeyPassword: []byte("mala"), CsrPem: csr.CsrPem, Profile: "server"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("contraseña mala: %v", err)
	}
	p12, err := sc.PkiExport(ctx(t), &v1.PkiExportRequest{Format: "p12", CertPem: cert.CertPem, ChainPem: ca.CaCertPem, SealedKeyPem: csr.SealedKeyPem,
		KeyPassword: []byte("MARKER-KPW"), ExportPassword: []byte("exp")})
	if err != nil {
		t.Fatal(err)
	}
	if _, c, _, err := pkcs12.DecodeChain(p12.Data, "exp"); err != nil || c.Subject.CommonName != "ise01.lab" {
		t.Fatalf("p12: %v", err)
	}
	if _, err := sc.PkiExport(ctx(t), &v1.PkiExportRequest{Format: "pem", CertPem: cert.CertPem, SealedKeyPem: csr.SealedKeyPem, KeyPassword: []byte("MARKER-KPW")}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("pem con llave sin include_plain_key: %v", err)
	}
	dec, err := sc.PkiDecode(ctx(t), &v1.PkiDecodeRequest{Data: []byte(cert.CertPem)})
	if err != nil || !strings.Contains(dec.Report.Text, "ise01.lab") {
		t.Fatalf("%v %v", dec, err)
	}
	if _, err := sc.PkiKey(ctx(t), &v1.PkiKeyRequest{Algorithm: "rsa1024", KeyPassword: []byte("x")}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("rsa1024: %v", err)
	}
	if _, err := sc.PkiKey(ctx(t), &v1.PkiKeyRequest{Algorithm: "p256"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("sin contraseña: %v", err)
	}
	txt := h.auditText(t)
	for _, a := range []string{"pki.ca.init", "pki.csr", "pki.ca.sign", "pki.export"} {
		if !strings.Contains(txt, `"action":"`+a+`"`) {
			t.Errorf("falta %s en auditoría", a)
		}
	}
	if strings.Contains(txt, "MARKER") {
		t.Fatal("contraseñas en auditoría")
	}
}

func TestIkeDecode(t *testing.T) {
	h := newHarness(t, nil)
	r, err := v1.NewSecurityServiceClient(h.conn).IkeDecode(ctx(t), &v1.IkeDecodeRequest{Text: "ISAKMP:(0): phase 1 SA policy not acceptable! (local 192.0.2.1 remote 192.0.2.2)\n"})
	if err != nil || !strings.Contains(r.Report.Text, "fase 1") {
		t.Fatalf("%v %v", r, err)
	}
}
