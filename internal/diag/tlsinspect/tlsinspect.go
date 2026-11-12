// Package tlsinspect revisa el TLS de un servicio (ISE, Catalyst Center, WLC, FMC
// o cualquier HTTPS): versiones aceptadas, cifrado, ALPN, cadena, vencimientos y
// nombre. Solo hace handshakes; nunca manda datos de aplicación.
package tlsinspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type Dialer func(ctx context.Context, network, host string, port uint16) (net.Conn, error)

type Options struct {
	Timeout time.Duration  // por handshake; 10 s por defecto
	Roots   *x509.CertPool // nil = raíces del sistema
	Now     func() time.Time
}

type Cert struct {
	Subject, Issuer string
	SANs            []string
	NotBefore       time.Time
	NotAfter        time.Time
	KeyType         string
	KeyBits         int
	SigAlg          string
	SHA256          string
	IsCA            bool
}

type Finding struct{ Severity, Code, Detail string }

type Report struct {
	Target      string
	SNI         string
	Version     string // la negociada con la configuración por defecto
	Cipher      string
	ALPN        string
	Accepted    []string // versiones que el servidor acepta
	Chain       []Cert
	Verified    bool
	VerifyError string `json:",omitempty"`
	NameMatches bool
	DaysLeft    int
	Findings    []Finding
}

var versions = []struct {
	v    uint16
	name string
}{{tls.VersionTLS10, "TLS 1.0"}, {tls.VersionTLS11, "TLS 1.1"}, {tls.VersionTLS12, "TLS 1.2"}, {tls.VersionTLS13, "TLS 1.3"}}

func versionName(v uint16) string {
	for _, x := range versions {
		if x.v == v {
			return x.name
		}
	}
	return fmt.Sprintf("0x%04x", v)
}

// handshake abre TCP, negocia TLS sin verificar (la verificación se hace aparte,
// para poder reportar la cadena aunque sea inválida) y cierra.
func handshake(ctx context.Context, d Dialer, host string, port uint16, sni string, minV, maxV uint16, timeout time.Duration) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := d(ctx, "tcp", host, port)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	tc := tls.Client(c, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // la cadena se verifica después con x509.Verify; aquí solo se observa
		MinVersion:         minV,
		MaxVersion:         maxV,
		NextProtos:         []string{"h2", "http/1.1"},
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	st := tc.ConnectionState()
	return st, nil
}

// Inspect hace el diagnóstico completo contra host:port con el SNI dado (vacío = host).
func Inspect(ctx context.Context, d Dialer, host string, port uint16, sni string, o Options) (Report, error) {
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	if sni == "" {
		sni = host
	}
	r := Report{Target: net.JoinHostPort(host, fmt.Sprint(port)), SNI: sni}
	add := func(sev, code, detail string) { r.Findings = append(r.Findings, Finding{sev, code, detail}) }

	st, err := handshake(ctx, d, host, port, sni, tls.VersionTLS12, tls.VersionTLS13, o.Timeout)
	if err != nil {
		// Puede que solo hable TLS 1.0/1.1; se intenta antes de rendirse.
		st, err = handshake(ctx, d, host, port, sni, tls.VersionTLS10, tls.VersionTLS11, o.Timeout)
		if err != nil {
			return r, fmt.Errorf("tlsinspect: el servicio no completó un handshake TLS: %w", err)
		}
	}
	r.Version, r.Cipher, r.ALPN = versionName(st.Version), tls.CipherSuiteName(st.CipherSuite), st.NegotiatedProtocol
	for _, v := range versions {
		if _, err := handshake(ctx, d, host, port, sni, v.v, v.v, o.Timeout); err == nil {
			r.Accepted = append(r.Accepted, v.name)
			if v.v < tls.VersionTLS12 {
				add("aviso", "tls-antiguo", v.name+" sigue habilitado; deshabilítalo")
			}
		}
	}
	for _, c := range st.PeerCertificates {
		r.Chain = append(r.Chain, describe(c))
	}
	if len(st.PeerCertificates) == 0 {
		return r, errors.New("tlsinspect: el servidor no presentó certificado")
	}
	leaf := st.PeerCertificates[0]
	r.DaysLeft = int(leaf.NotAfter.Sub(now).Hours() / 24)
	if leaf.NotAfter.Before(now) {
		r.DaysLeft = -int(now.Sub(leaf.NotAfter).Hours()/24) - 1
	}
	r.NameMatches = leaf.VerifyHostname(sni) == nil
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: sni, Roots: o.Roots, Intermediates: inter, CurrentTime: now})
	r.Verified = verr == nil
	if verr != nil {
		r.VerifyError = verr.Error()
	}
	switch {
	case now.After(leaf.NotAfter):
		add("error", "vencido", fmt.Sprintf("el certificado venció el %s", leaf.NotAfter.UTC().Format(time.RFC3339)))
	case now.Before(leaf.NotBefore):
		add("error", "aun-no-valido", fmt.Sprintf("el certificado es válido desde %s", leaf.NotBefore.UTC().Format(time.RFC3339)))
	case leaf.NotAfter.Sub(now) < 30*24*time.Hour:
		add("aviso", "vence-pronto", fmt.Sprintf("el certificado vence en %d días", r.DaysLeft))
	}
	if !r.NameMatches {
		add("error", "nombre-no-coincide", fmt.Sprintf("el certificado no cubre %q (SAN: %s)", sni, strings.Join(leaf.DNSNames, ", ")))
	}
	// CheckSignatureFrom exige que el emisor sea CA; un autofirmado de servidor no lo es.
	if leaf.Subject.String() == leaf.Issuer.String() && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
		add("aviso", "autofirmado", "el certificado es autofirmado; los clientes no lo validarán sin fijarlo")
	}
	var ua x509.UnknownAuthorityError
	if errors.As(verr, &ua) && !hasCode(r.Findings, "autofirmado") {
		add("error", "cadena-incompleta", "no se pudo construir la cadena hasta una raíz de confianza (¿falta el intermedio?)")
	}
	for i, c := range r.Chain {
		if c.KeyType == "RSA" && c.KeyBits < 2048 {
			add("aviso", "llave-debil", fmt.Sprintf("certificado %d con RSA de %d bits", i, c.KeyBits))
		}
		if strings.Contains(c.SigAlg, "SHA1") || strings.Contains(c.SigAlg, "MD5") {
			add("aviso", "firma-debil", fmt.Sprintf("certificado %d firmado con %s", i, c.SigAlg))
		}
	}
	return r, nil
}

func hasCode(fs []Finding, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func describe(c *x509.Certificate) Cert {
	sum := sha256.Sum256(c.Raw)
	out := Cert{Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotBefore: c.NotBefore, NotAfter: c.NotAfter, SigAlg: c.SignatureAlgorithm.String(),
		SHA256: strings.ToUpper(hex.EncodeToString(sum[:])), IsCA: c.IsCA}
	out.SANs = append(out.SANs, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out.SANs = append(out.SANs, ip.String())
	}
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		out.KeyType, out.KeyBits = "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		out.KeyType, out.KeyBits = "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		out.KeyType, out.KeyBits = "Ed25519", 256
	default:
		out.KeyType = "desconocida"
	}
	return out
}
