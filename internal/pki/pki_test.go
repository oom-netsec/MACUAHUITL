package pki

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

var params = vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1}

func TestMain(m *testing.M) {
	vault.MinMemoryKiB = 8192
	os.Exit(m.Run())
}

var now = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func TestKeyAlgorithmsAndSealing(t *testing.T) {
	for alg, check := range map[string]func(any) bool{
		"rsa2048": func(k any) bool { r, ok := k.(*rsa.PrivateKey); return ok && r.N.BitLen() == 2048 },
		"p256":    func(k any) bool { e, ok := k.(*ecdsa.PrivateKey); return ok && e.Curve.Params().BitSize == 256 },
		"p384":    func(k any) bool { e, ok := k.(*ecdsa.PrivateKey); return ok && e.Curve.Params().BitSize == 384 },
	} {
		k, err := GenerateKey(alg)
		if err != nil || !check(k) {
			t.Fatalf("%s: %T %v", alg, k, err)
		}
		sealed, err := SealKey(k, []byte("pw"), params)
		if err != nil || !strings.Contains(string(sealed), "MACUAHUITL SEALED PRIVATE KEY") {
			t.Fatalf("%s: %v", alg, err)
		}
		back, err := OpenKey(sealed, []byte("pw"))
		if err != nil || !check(back) {
			t.Fatalf("%s: abrir: %v", alg, err)
		}
		if _, err := OpenKey(sealed, []byte("mala")); err == nil {
			t.Fatal("contraseña incorrecta aceptada")
		}
	}
	for _, bad := range []string{"rsa1024", "ed448", ""} {
		if _, err := GenerateKey(bad); err == nil {
			t.Errorf("%q aceptado", bad)
		}
	}
}

func TestCSRAndLabCASigning(t *testing.T) {
	caKey, _ := GenerateKey("p256")
	caPEM, err := InitCA(caKey, "MACUAHUITL Lab CA", 3650, now)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := GenerateKey("rsa2048")
	csr, err := CreateCSR(leafKey, CSRRequest{Subject: Subject{CN: "ise01.lab.local", O: "Lab", C: "MX"},
		DNS: []string{"ise01.lab.local", "ise01"}, IPs: []string{"10.0.0.10"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CreateCSR(leafKey, CSRRequest{Subject: Subject{CN: "x"}, IPs: []string{"nope"}}); err == nil {
		t.Fatal("IP inválida aceptada")
	}
	for profile, eku := range map[string]x509.ExtKeyUsage{"server": x509.ExtKeyUsageServerAuth, "client": x509.ExtKeyUsageClientAuth} {
		certPEM, err := Sign(caPEM, caKey, csr, profile, 365, now)
		if err != nil {
			t.Fatal(err)
		}
		c := parse(t, certPEM)
		ca := parse(t, caPEM)
		if err := c.CheckSignatureFrom(ca); err != nil {
			t.Fatal(err)
		}
		if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != eku || c.IsCA || c.Subject.CommonName != "ise01.lab.local" {
			t.Fatalf("%s: %+v", profile, c.ExtKeyUsage)
		}
		if len(c.DNSNames) != 2 || len(c.IPAddresses) != 1 || !c.NotAfter.Equal(now.Add(365*24*time.Hour).Truncate(time.Second)) {
			t.Fatalf("%s: SAN/validez %v %v %v", profile, c.DNSNames, c.IPAddresses, c.NotAfter)
		}
		if c.KeyUsage&x509.KeyUsageKeyEncipherment == 0 { // RSA: TLS 1.2 con intercambio RSA lo exige
			t.Error("RSA sin keyEncipherment")
		}
	}
	if _, err := Sign(caPEM, caKey, csr, "frob", 365, now); err == nil {
		t.Fatal("perfil desconocido aceptado")
	}
	other, _ := GenerateKey("p256")
	if _, err := Sign(caPEM, other, csr, "server", 365, now); err == nil {
		t.Fatal("llave que no corresponde a la CA aceptada")
	}
	tampered := []byte(strings.Replace(string(csr), "A", "B", 1))
	if _, err := Sign(caPEM, caKey, tampered, "server", 365, now); err == nil {
		t.Fatal("CSR alterado aceptado")
	}
}

func parse(t *testing.T, p []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(p)
	if b == nil {
		t.Fatal("PEM inválido")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDecodeSummaries(t *testing.T) {
	caKey, _ := GenerateKey("p256")
	caPEM, _ := InitCA(caKey, "Lab CA", 30, now)
	k, _ := GenerateKey("p256")
	csr, _ := CreateCSR(k, CSRRequest{Subject: Subject{CN: "wlc.lab"}})
	sums, err := Decode(append(append([]byte{}, caPEM...), csr...), now.Add(60*24*time.Hour))
	if err != nil || len(sums) != 2 {
		t.Fatalf("%+v %v", sums, err)
	}
	if sums[0].Kind != "certificado" || !sums[0].IsCA || sums[0].DaysLeft >= 0 || !has(sums[0].Warnings, "vencido") {
		t.Fatalf("CA: %+v", sums[0])
	}
	if sums[1].Kind != "CSR" || !sums[1].SignatureValid || !has(sums[1].Warnings, "sin SAN") {
		t.Fatalf("CSR: %+v", sums[1])
	}
	block, _ := pem.Decode(caPEM)
	if s, err := Decode(block.Bytes, now); err != nil || !strings.HasPrefix(s[0].Subject, "CN=Lab CA") { // DER
		t.Fatalf("DER: %+v %v", s, err)
	}
	if !strings.Contains(Text(sums), "SHA-256") {
		t.Fatal(Text(sums))
	}
	for _, junk := range [][]byte{nil, []byte("hola"), []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")} {
		if _, err := Decode(junk, now); err == nil {
			t.Errorf("%q aceptado", junk)
		}
	}
}

func has(l []string, sub string) bool {
	for _, s := range l {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func TestExportFormats(t *testing.T) {
	caKey, _ := GenerateKey("p256")
	caPEM, _ := InitCA(caKey, "Lab CA", 30, now)
	k, _ := GenerateKey("rsa2048")
	csr, _ := CreateCSR(k, CSRRequest{Subject: Subject{CN: "h"}, DNS: []string{"h"}})
	cert, _ := Sign(caPEM, caKey, csr, "server", 30, now)
	for _, f := range []string{"p12", "p12-legacy"} {
		out, err := Export(f, cert, caPEM, k, "export-pw")
		if err != nil {
			t.Fatal(err)
		}
		key, c, chain, err := pkcs12.DecodeChain(out, "export-pw")
		if err != nil || c.Subject.CommonName != "h" || len(chain) != 1 || key == nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if _, err := Export("p12", cert, caPEM, k, ""); err == nil {
		t.Fatal("PKCS#12 sin contraseña aceptado")
	}
	der, _ := Export("der", cert, nil, nil, "")
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	p, _ := Export("pem", cert, caPEM, nil, "")
	if strings.Count(string(p), "BEGIN CERTIFICATE") != 2 || strings.Contains(string(p), "PRIVATE") {
		t.Fatal(string(p))
	}
	p, _ = Export("pem", cert, nil, k, "")
	if !strings.Contains(string(p), "BEGIN PRIVATE KEY") {
		t.Fatal("PEM con llave explícita sin llave")
	}
	if _, err := Export("p12", cert, nil, caKey, "x"); err == nil {
		t.Fatal("llave que no corresponde al certificado aceptada")
	}
}
