package tlsinspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type certSpec struct {
	name      string
	notBefore time.Time
	notAfter  time.Time
	selfSign  bool
	rsaBits   int
}

// issue arma un certificado según spec, firmado por ca (o autofirmado).
func issue(t *testing.T, ca *x509.Certificate, caKey any, s certSpec) tls.Certificate {
	t.Helper()
	var pub, priv any
	if s.rsaBits > 0 {
		k, _ := rsa.GenerateKey(rand.Reader, s.rsaBits)
		pub, priv = &k.PublicKey, k
	} else {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub, priv = &k.PublicKey, k
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: s.name}, DNSNames: []string{s.name},
		NotBefore: s.notBefore, NotAfter: s.notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	parent, signer := ca, caKey
	if s.selfSign {
		parent, signer = tmpl, priv
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}
}

func newCA(t *testing.T) (*x509.Certificate, any, *x509.CertPool) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA de laboratorio"}, NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return c, k, pool
}

func serve(t *testing.T, cert tls.Certificate, minV, maxV uint16) uint16 {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: minV, MaxVersion: maxV, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func dial(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, netip.AddrPortFrom(netip.MustParseAddr(host), port).String())
}

func codes(r Report) map[string]bool {
	m := map[string]bool{}
	for _, f := range r.Findings {
		m[f.Code] = true
	}
	return m
}

func TestValidCertificate(t *testing.T) {
	ca, key, pool := newCA(t)
	port := serve(t, issue(t, ca, key, certSpec{name: "ise.lab", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(200 * 24 * time.Hour)}), tls.VersionTLS12, tls.VersionTLS13)
	r, err := Inspect(context.Background(), dial, "127.0.0.1", port, "ise.lab", Options{Roots: pool})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Verified || !r.NameMatches || r.Version != "TLS 1.3" || r.ALPN != "h2" || len(r.Chain) != 1 || r.Chain[0].Subject != "CN=ise.lab" || r.DaysLeft < 199 {
		t.Fatalf("r=%+v", r)
	}
	if len(r.Accepted) != 2 || codes(r)["tls-antiguo"] {
		t.Fatalf("accepted=%v findings=%+v", r.Accepted, r.Findings)
	}
}

func TestExpiredAndExpiring(t *testing.T) {
	ca, key, pool := newCA(t)
	exp := serve(t, issue(t, ca, key, certSpec{name: "wlc.lab", notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)}), tls.VersionTLS12, tls.VersionTLS13)
	r, err := Inspect(context.Background(), dial, "127.0.0.1", exp, "wlc.lab", Options{Roots: pool})
	if err != nil || r.Verified || !codes(r)["vencido"] || r.DaysLeft >= 0 {
		t.Fatalf("expired: r=%+v err=%v", r, err)
	}
	soon := serve(t, issue(t, ca, key, certSpec{name: "wlc.lab", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(10 * 24 * time.Hour)}), tls.VersionTLS12, tls.VersionTLS13)
	r, _ = Inspect(context.Background(), dial, "127.0.0.1", soon, "wlc.lab", Options{Roots: pool})
	if !r.Verified || !codes(r)["vence-pronto"] {
		t.Fatalf("expiring: %+v", r.Findings)
	}
}

func TestSelfSignedAndWrongName(t *testing.T) {
	_, _, pool := newCA(t)
	self := serve(t, issue(t, nil, nil, certSpec{name: "fmc.lab", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour), selfSign: true}), tls.VersionTLS12, tls.VersionTLS13)
	r, err := Inspect(context.Background(), dial, "127.0.0.1", self, "fmc.lab", Options{Roots: pool})
	if err != nil || r.Verified || !codes(r)["autofirmado"] || len(r.Chain) != 1 {
		t.Fatalf("self-signed: r=%+v err=%v", r, err)
	}
	ca, key, pool2 := newCA(t)
	wrong := serve(t, issue(t, ca, key, certSpec{name: "otro.lab", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour)}), tls.VersionTLS12, tls.VersionTLS13)
	r, _ = Inspect(context.Background(), dial, "127.0.0.1", wrong, "ise.lab", Options{Roots: pool2})
	if r.NameMatches || !codes(r)["nombre-no-coincide"] || r.Verified {
		t.Fatalf("wrong name: %+v", r)
	}
}

func TestWeakRSAKey(t *testing.T) {
	ca, key, pool := newCA(t)
	port := serve(t, issue(t, ca, key, certSpec{name: "old.lab", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour), rsaBits: 1024}), tls.VersionTLS12, tls.VersionTLS12)
	r, _ := Inspect(context.Background(), dial, "127.0.0.1", port, "old.lab", Options{Roots: pool})
	if !codes(r)["llave-debil"] || r.Chain[0].KeyBits != 1024 {
		t.Fatalf("weak key: %+v", r)
	}
}

func TestOnlyTLS13(t *testing.T) {
	ca, key, pool := newCA(t)
	port := serve(t, issue(t, ca, key, certSpec{name: "cc.lab", notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(time.Hour)}), tls.VersionTLS13, tls.VersionTLS13)
	r, err := Inspect(context.Background(), dial, "127.0.0.1", port, "cc.lab", Options{Roots: pool})
	if err != nil || len(r.Accepted) != 1 || r.Accepted[0] != "TLS 1.3" {
		t.Fatalf("accepted=%v err=%v", r.Accepted, err)
	}
}

func TestNotTLS(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Write([]byte("SSH-2.0-OpenSSH\r\n"))
			c.Close()
		}
	}()
	_, err := Inspect(context.Background(), dial, "127.0.0.1", uint16(ln.Addr().(*net.TCPAddr).Port), "", Options{Timeout: 500 * time.Millisecond})
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("err = %v", err)
	}
}
