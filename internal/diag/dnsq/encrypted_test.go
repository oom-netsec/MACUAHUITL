package dnsq

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// testCert emite un certificado para name, firmado por una CA de prueba.
func testCert(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA de prueba"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func direct(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, netip.AddrPortFrom(netip.MustParseAddr(host), port).String())
}

func TestQueryDoT(t *testing.T) {
	cert, pool := testCert(t, "dot.lab")
	ln, err := tls.Listen("tcp", "127.0.0.60:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: newZone("dot.lab.").add("dot.lab. 60 IN A 192.0.2.53")}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	o := opts()
	o.TLSRoots = pool
	a, err := Query(context.Background(), direct, Server{Transport: "dot", Host: "127.0.0.60", Port: port, TLSName: "dot.lab"}, "dot.lab", dns.TypeA, o)
	if err != nil || len(a.Answer) != 1 {
		t.Fatalf("a=%+v err=%v", a, err)
	}
	// Nombre de certificado equivocado: debe fallar, nunca aceptar.
	if _, err := Query(context.Background(), direct, Server{Transport: "dot", Host: "127.0.0.60", Port: port, TLSName: "otro.lab"}, "dot.lab", dns.TypeA, o); err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("wrong TLS name accepted: %v", err)
	}
}

func TestQueryDoH(t *testing.T) {
	cert, pool := testCert(t, "doh.lab")
	z := newZone("doh.lab.").add("doh.lab. 60 IN A 192.0.2.54")
	ln, err := tls.Listen("tcp", "127.0.0.61:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		b, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if q.Unpack(b) != nil {
			http.Error(w, "no", http.StatusBadRequest)
			return
		}
		rw := &dohWriter{}
		z.ServeDNS(rw, q)
		out, _ := rw.m.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(out)
	})}
	go hs.Serve(ln)
	t.Cleanup(func() { hs.Close() })
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	o := opts()
	o.TLSRoots = pool
	// El servidor DoH se nombra por IP en la prueba; TLSName es el del certificado.
	a, err := Query(context.Background(), direct, Server{Transport: "doh", Host: "127.0.0.61", Port: port, TLSName: "doh.lab", Path: "/dns-query"}, "doh.lab", dns.TypeA, o)
	if err != nil || len(a.Answer) != 1 || !strings.Contains(a.Answer[0], "192.0.2.54") {
		t.Fatalf("a=%+v err=%v", a, err)
	}
}

// dohWriter adapta ServeDNS a una respuesta HTTP.
type dohWriter struct{ m *dns.Msg }

func (w *dohWriter) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (w *dohWriter) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (w *dohWriter) WriteMsg(m *dns.Msg) error   { w.m = m; return nil }
func (w *dohWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *dohWriter) Close() error                { return nil }
func (w *dohWriter) TsigStatus() error           { return nil }
func (w *dohWriter) TsigTimersOnly(bool)         {}
func (w *dohWriter) Hijack()                     {}
