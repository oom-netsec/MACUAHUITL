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

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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

type Finding struct {
	Severity, Code, Detail string
	Text                   i18n.Text `json:"-"` // Detail como texto de catálogo (para darlo en otro idioma)
}

// finding arma un hallazgo con el detalle de catálogo; Detail sale en español, el de siempre.
func finding(sev, code, key string, kv ...any) Finding {
	t := i18n.Tx(key, kv...)
	return Finding{sev, code, t.In(i18n.Es), t}
}

// SeverityCode da la severidad cerrada en inglés (el JSON conserva aviso, error e info).
func SeverityCode(s string) string {
	if s == "aviso" {
		return "warning"
	}
	return s
}

// In devuelve el informe con el detalle de cada hallazgo en el idioma dado (es es el de siempre). VerifyError es
// el texto del sistema (el de la biblioteca x509) y no se traduce: VerifyCode lo clasifica.
func (r Report) In(loc string) Report {
	if r.Findings == nil { // nulo sigue nulo: el JSON en español no cambia
		return r
	}
	fs := make([]Finding, len(r.Findings))
	for i, f := range r.Findings {
		f.Detail = f.Text.In(loc)
		fs[i] = f
	}
	r.Findings = fs
	return r
}

// verifyCode clasifica el error de verificación de la cadena en un código cerrado.
func verifyCode(err error, leaf *x509.Certificate, now time.Time) string {
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	var he x509.HostnameError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &ua):
		return "unknown_authority"
	case errors.As(err, &he):
		return "hostname"
	case errors.As(err, &ci) && ci.Reason == x509.Expired:
		if now.Before(leaf.NotBefore) {
			return "not_yet_valid"
		}
		return "expired"
	}
	return "other"
}

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
	VerifyCode  string `json:"-"` // unknown_authority, hostname, expired, not_yet_valid u other; vacío si verificó
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
	add := func(sev, code, key string, kv ...any) {
		r.Findings = append(r.Findings, finding(sev, code, key, kv...))
	}

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
				add("aviso", "tls-antiguo", "tls.finding.legacy_version", "version", v.name)
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
		r.VerifyError, r.VerifyCode = verr.Error(), verifyCode(verr, leaf, now)
	}
	switch {
	case now.After(leaf.NotAfter):
		add("error", "vencido", "tls.finding.expired", "date", leaf.NotAfter.UTC().Format(time.RFC3339))
	case now.Before(leaf.NotBefore):
		add("error", "aun-no-valido", "tls.finding.not_yet_valid", "date", leaf.NotBefore.UTC().Format(time.RFC3339))
	case leaf.NotAfter.Sub(now) < 30*24*time.Hour:
		add("aviso", "vence-pronto", "tls.finding.expires_soon", "days", r.DaysLeft)
	}
	if !r.NameMatches {
		add("error", "nombre-no-coincide", "tls.finding.name_mismatch", "name", sni, "san", strings.Join(leaf.DNSNames, ", "))
	}
	// CheckSignatureFrom exige que el emisor sea CA; un autofirmado de servidor no lo es.
	if leaf.Subject.String() == leaf.Issuer.String() && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil {
		add("aviso", "autofirmado", "tls.finding.self_signed")
	}
	var ua x509.UnknownAuthorityError
	if errors.As(verr, &ua) && !hasCode(r.Findings, "autofirmado") {
		add("error", "cadena-incompleta", "tls.finding.incomplete_chain")
	}
	for i, c := range r.Chain {
		if c.KeyType == "RSA" && c.KeyBits < 2048 {
			add("aviso", "llave-debil", "tls.finding.weak_key", "index", i, "bits", c.KeyBits)
		}
		if strings.Contains(c.SigAlg, "SHA1") || strings.Contains(c.SigAlg, "MD5") {
			add("aviso", "firma-debil", "tls.finding.weak_signature", "index", i, "algorithm", c.SigAlg)
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
