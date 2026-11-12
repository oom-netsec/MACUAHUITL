// Package pki genera llaves y CSR listos para ISE, Catalyst Center o WLC, firma
// con una CA de laboratorio local y resume certificados o CSR pegados. Sin red.
//
// La CA es SOLO de laboratorio: no tiene CRL ni OCSP ni protección de hardware.
// Las llaves privadas se guardan selladas con vault.Seal (Argon2id + AES-256-GCM).
package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

const (
	SealedPEMType = "MACUAHUITL SEALED PRIVATE KEY"
	maxLeafDays   = 3650
	maxCADays     = 7300
)

// Algorithms son los algoritmos de llave aceptados.
var Algorithms = []string{"rsa2048", "rsa3072", "rsa4096", "p256", "p384"}

func GenerateKey(alg string) (crypto.Signer, error) {
	switch alg {
	case "rsa2048", "rsa3072", "rsa4096":
		bits := map[string]int{"rsa2048": 2048, "rsa3072": 3072, "rsa4096": 4096}[alg]
		return rsa.GenerateKey(rand.Reader, bits)
	case "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	}
	return nil, fmt.Errorf("pki: algoritmo %q no soportado (%s)", alg, strings.Join(Algorithms, ", "))
}

// SealKey sella la llave en PKCS#8 dentro de un sobre MCK1 y la devuelve en PEM.
func SealKey(k crypto.Signer, password []byte, p vault.Params) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	defer clear(der)
	blob, err := vault.Seal(password, der, p)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: SealedPEMType, Bytes: blob}), nil
}

func OpenKey(sealed, password []byte) (crypto.Signer, error) {
	b, _ := pem.Decode(sealed)
	if b == nil || b.Type != SealedPEMType {
		return nil, errors.New("pki: no es una llave sellada por MACUAHUITL (" + SealedPEMType + ")")
	}
	der, err := vault.Unseal(password, b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: abrir la llave: %w", err)
	}
	defer clear(der)
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("pki: tipo de llave no soportado")
	}
	return s, nil
}

type Subject struct {
	CN, O, OU, L, ST, C string
}

func (s Subject) name() pkix.Name {
	n := pkix.Name{CommonName: s.CN}
	for dst, v := range map[*[]string]string{&n.Organization: s.O, &n.OrganizationalUnit: s.OU, &n.Locality: s.L, &n.Province: s.ST, &n.Country: s.C} {
		if v != "" {
			*dst = []string{v}
		}
	}
	return n
}

type CSRRequest struct {
	Subject Subject
	DNS     []string
	IPs     []string
}

func CreateCSR(k crypto.Signer, r CSRRequest) ([]byte, error) {
	if strings.TrimSpace(r.Subject.CN) == "" {
		return nil, errors.New("pki: falta el CN")
	}
	if c := r.Subject.C; c != "" && len(c) != 2 {
		return nil, errors.New("pki: el país (C) es de 2 letras ISO 3166")
	}
	tpl := &x509.CertificateRequest{Subject: r.Subject.name(), DNSNames: r.DNS}
	for _, s := range r.IPs {
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("pki: IP %q inválida", s)
		}
		tpl.IPAddresses = append(tpl.IPAddresses, ip.AsSlice()) // pki no importa net (noegress)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func validity(days, max int, now time.Time) (time.Time, time.Time, error) {
	if days <= 0 || days > max {
		return time.Time{}, time.Time{}, fmt.Errorf("pki: validez de %d días fuera de 1–%d", days, max)
	}
	now = now.Truncate(time.Second)
	return now.Add(-5 * time.Minute), now.Add(time.Duration(days) * 24 * time.Hour), nil // margen para relojes desfasados
}

// InitCA crea la raíz autofirmada de laboratorio (pathlen 0: no admite subordinadas).
func InitCA(k crypto.Signer, cn string, days int, now time.Time) ([]byte, error) {
	if strings.TrimSpace(cn) == "" {
		return nil, errors.New("pki: falta el nombre de la CA")
	}
	nb, na, err := validity(days, maxCADays, now)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn, OrganizationalUnit: []string{"Laboratorio - no confiable"}},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, k.Public(), k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

var profiles = map[string][]x509.ExtKeyUsage{
	"server":        {x509.ExtKeyUsageServerAuth},
	"client":        {x509.ExtKeyUsageClientAuth},
	"server-client": {x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
}

func firstCert(p []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(p)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("pki: se esperaba un certificado PEM")
	}
	return x509.ParseCertificate(b.Bytes)
}

type publicKey interface{ Equal(crypto.PublicKey) bool }

func sameKey(a, b crypto.PublicKey) bool {
	pa, ok := a.(publicKey)
	return ok && pa.Equal(b)
}

// Sign firma csrPEM con la CA. Copia del CSR solo el Subject, los SAN y la llave;
// usos y validez los pone el perfil, nunca el solicitante.
func Sign(caPEM []byte, caKey crypto.Signer, csrPEM []byte, profile string, days int, now time.Time) ([]byte, error) {
	ca, err := firstCert(caPEM)
	if err != nil {
		return nil, err
	}
	if !ca.IsCA {
		return nil, errors.New("pki: el certificado indicado no es de una CA")
	}
	eku, ok := profiles[profile]
	if !ok {
		return nil, fmt.Errorf("pki: perfil %q desconocido (server, client, server-client)", profile)
	}
	b, _ := pem.Decode(csrPEM)
	if b == nil || !strings.HasSuffix(b.Type, "CERTIFICATE REQUEST") {
		return nil, errors.New("pki: se esperaba un CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("pki: CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: la firma del CSR no verifica: %w", err)
	}
	nb, na, err := validity(days, maxLeafDays, now)
	if err != nil {
		return nil, err
	}
	if na.After(ca.NotAfter) {
		na = ca.NotAfter
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	ku := x509.KeyUsageDigitalSignature
	if _, isRSA := csr.PublicKey.(*rsa.PublicKey); isRSA {
		ku |= x509.KeyUsageKeyEncipherment
	}
	tpl := &x509.Certificate{SerialNumber: sn, Subject: csr.Subject, DNSNames: csr.DNSNames, IPAddresses: csr.IPAddresses,
		NotBefore: nb, NotAfter: na, KeyUsage: ku, ExtKeyUsage: eku, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca, csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// Export: pem (certificado y cadena; la llave en claro solo si se pasa), der
// (solo certificado), p12 (AES-256/PBKDF2) o p12-legacy (3DES, para equipos viejos).
func Export(format string, certPEM, chainPEM []byte, key crypto.Signer, password string) ([]byte, error) {
	cert, err := firstCert(certPEM)
	if err != nil {
		return nil, err
	}
	var chain []*x509.Certificate
	for rest := chainPEM; ; {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: cadena: %w", err)
		}
		chain = append(chain, c)
	}
	if key != nil && !sameKey(cert.PublicKey, key.Public()) {
		return nil, errors.New("pki: la llave no corresponde al certificado")
	}
	switch format {
	case "der":
		return cert.Raw, nil
	case "pem":
		var out bytes.Buffer
		for _, c := range append([]*x509.Certificate{cert}, chain...) {
			pem.Encode(&out, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
		}
		if key != nil {
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return nil, err
			}
			pem.Encode(&out, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
			clear(der)
		}
		return out.Bytes(), nil
	case "p12", "p12-legacy":
		if key == nil || password == "" {
			return nil, errors.New("pki: PKCS#12 necesita la llave y una contraseña de exportación")
		}
		enc := pkcs12.Modern2023
		if format == "p12-legacy" {
			enc = pkcs12.LegacyDES
		}
		return enc.Encode(key, cert, chain, password)
	}
	return nil, fmt.Errorf("pki: formato %q desconocido (pem, der, p12, p12-legacy)", format)
}

// Summary es el resumen legible de un certificado o CSR.
type Summary struct {
	Kind           string // certificado o CSR
	Subject        string
	Issuer         string `json:",omitempty"`
	Serial         string `json:",omitempty"`
	NotBefore      string `json:",omitempty"`
	NotAfter       string `json:",omitempty"`
	DaysLeft       int    `json:",omitempty"`
	KeyType        string
	SigAlg         string
	SANs           []string `json:",omitempty"`
	KeyUsage       []string `json:",omitempty"`
	ExtKeyUsage    []string `json:",omitempty"`
	IsCA           bool
	SelfSigned     bool     `json:",omitempty"`
	SignatureValid bool     `json:",omitempty"` // CSR
	SHA1           string   `json:",omitempty"`
	SHA256         string   `json:",omitempty"`
	Warnings       []string `json:",omitempty"`

	// Lo que sigue no viaja en el JSON: es lo mismo de arriba en forma estructurada.
	KeyAlg    string      `json:"-"` // RSA o ECDSA
	KeyBits   int         `json:"-"` // bits del módulo RSA o de la curva
	KeyCurve  string      `json:"-"` // nombre de la curva ECDSA
	WarnItems []i18n.Text `json:"-"` // Warnings como textos de catálogo (misma longitud y orden)
}

// LabWarning es el aviso de las CA de laboratorio, en español (el catálogo lo da también en inglés; una prueba
// verifica que sean el mismo texto).
const LabWarning = "CA SOLO DE LABORATORIO: no la instales como raíz de confianza fuera del laboratorio ni firmes con ella equipos de producción."

// warn agrega un aviso del catálogo al texto en español y a su forma estructurada.
func (s *Summary) warn(key string, kv ...any) {
	t := i18n.Tx(key, kv...)
	s.Warnings = append(s.Warnings, t.In(i18n.Es))
	s.WarnItems = append(s.WarnItems, t)
}

// setKey llena la llave en forma estructurada.
func (s *Summary) setKey(k any) {
	switch p := k.(type) {
	case *rsa.PublicKey:
		s.KeyAlg, s.KeyBits = "RSA", p.N.BitLen()
	case *ecdsa.PublicKey:
		s.KeyAlg, s.KeyBits, s.KeyCurve = "ECDSA", p.Curve.Params().BitSize, p.Curve.Params().Name
	}
}

var kuNames = []struct {
	b x509.KeyUsage
	n string
}{{x509.KeyUsageDigitalSignature, "digitalSignature"}, {x509.KeyUsageContentCommitment, "nonRepudiation"},
	{x509.KeyUsageKeyEncipherment, "keyEncipherment"}, {x509.KeyUsageDataEncipherment, "dataEncipherment"},
	{x509.KeyUsageKeyAgreement, "keyAgreement"}, {x509.KeyUsageCertSign, "keyCertSign"}, {x509.KeyUsageCRLSign, "cRLSign"}}

var ekuNames = map[x509.ExtKeyUsage]string{x509.ExtKeyUsageServerAuth: "serverAuth", x509.ExtKeyUsageClientAuth: "clientAuth",
	x509.ExtKeyUsageCodeSigning: "codeSigning", x509.ExtKeyUsageEmailProtection: "emailProtection", x509.ExtKeyUsageIPSECEndSystem: "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel: "ipsecTunnel", x509.ExtKeyUsageIPSECUser: "ipsecUser", x509.ExtKeyUsageOCSPSigning: "OCSPSigning", x509.ExtKeyUsageAny: "any"}

func keyInfo(k any) string {
	switch p := k.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", p.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + p.Curve.Params().Name
	}
	return fmt.Sprintf("%T", k)
}

func sans[IP ~[]byte](dns []string, ips []IP, emails []string) []string {
	out := append([]string(nil), dns...)
	for _, ip := range ips {
		a, _ := netip.AddrFromSlice(ip)
		out = append(out, "IP:"+a.Unmap().String())
	}
	for _, e := range emails {
		out = append(out, "email:"+e)
	}
	return out
}

func warnKey(k any, s *Summary) {
	if r, ok := k.(*rsa.PublicKey); ok && r.N.BitLen() < 2048 {
		s.warn("security.pki.warn.rsa_small")
	}
	if strings.Contains(strings.ToLower(s.SigAlg), "sha1") || strings.Contains(strings.ToLower(s.SigAlg), "md5") {
		s.warn("security.pki.warn.weak_sig", "algorithm", s.SigAlg)
	}
	if len(s.SANs) == 0 && !s.IsCA {
		s.warn("security.pki.warn.no_san")
	}
}

func summarizeCert(c *x509.Certificate, now time.Time) Summary {
	s := Summary{Kind: "certificado", Subject: c.Subject.String(), Issuer: c.Issuer.String(), Serial: strings.ToUpper(c.SerialNumber.Text(16)),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft: int(c.NotAfter.Sub(now).Hours() / 24), KeyType: keyInfo(c.PublicKey), SigAlg: c.SignatureAlgorithm.String(),
		SANs: sans(c.DNSNames, c.IPAddresses, c.EmailAddresses), IsCA: c.IsCA}
	for _, k := range kuNames {
		if c.KeyUsage&k.b != 0 {
			s.KeyUsage = append(s.KeyUsage, k.n)
		}
	}
	for _, e := range c.ExtKeyUsage {
		s.ExtKeyUsage = append(s.ExtKeyUsage, ekuNames[e])
	}
	h1, h256 := sha1.Sum(c.Raw), sha256.Sum256(c.Raw)
	s.SHA1, s.SHA256 = strings.ToUpper(hex.EncodeToString(h1[:])), strings.ToUpper(hex.EncodeToString(h256[:]))
	s.SelfSigned = bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil
	switch {
	case now.After(c.NotAfter):
		s.warn("security.pki.warn.expired")
	case now.Before(c.NotBefore):
		s.warn("security.pki.warn.not_yet")
	case s.DaysLeft < 30:
		s.warn("security.pki.warn.expires_soon", "days", s.DaysLeft)
	}
	if s.SelfSigned && !c.IsCA {
		s.warn("security.pki.warn.self_signed")
	}
	s.setKey(c.PublicKey)
	warnKey(c.PublicKey, &s)
	return s
}

func summarizeCSR(r *x509.CertificateRequest) Summary {
	s := Summary{Kind: "CSR", Subject: r.Subject.String(), KeyType: keyInfo(r.PublicKey), SigAlg: r.SignatureAlgorithm.String(),
		SANs: sans(r.DNSNames, r.IPAddresses, r.EmailAddresses), SignatureValid: r.CheckSignature() == nil}
	if !s.SignatureValid {
		s.warn("security.pki.warn.csr_signature")
	}
	s.setKey(r.PublicKey)
	warnKey(r.PublicKey, &s)
	return s
}

// Decode acepta uno o varios bloques PEM (certificados y CSR) o un DER suelto.
func Decode(in []byte, now time.Time) ([]Summary, error) {
	var out []Summary
	rest := in
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			break
		}
		switch {
		case b.Type == "CERTIFICATE":
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: certificado: %w", err)
			}
			out = append(out, summarizeCert(c, now))
		case strings.HasSuffix(b.Type, "CERTIFICATE REQUEST"):
			r, err := x509.ParseCertificateRequest(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: CSR: %w", err)
			}
			out = append(out, summarizeCSR(r))
		default:
			return nil, fmt.Errorf("pki: bloque PEM %q no soportado (solo certificados y CSR; no pegues llaves privadas)", b.Type)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	if c, err := x509.ParseCertificate(in); err == nil {
		return []Summary{summarizeCert(c, now)}, nil
	}
	if r, err := x509.ParseCertificateRequest(in); err == nil {
		return []Summary{summarizeCSR(r)}, nil
	}
	return nil, errors.New("pki: no se reconoce un certificado ni un CSR (PEM o DER)")
}

// Text es el informe legible en español.
func Text(sums []Summary) string { return TextIn(sums, i18n.Es) }

// TextIn es el informe legible en el idioma pedido (etiquetas, «sí/no» y avisos); los valores (nombres,
// fechas, series, huellas, usos de llave) salen tal cual. Con es es el texto de siempre.
func TextIn(sums []Summary, loc string) string {
	var b strings.Builder
	m := func(key string) string { return i18n.Msg(loc, key, nil) }
	yesNo := func(v bool) string { return m(map[bool]string{true: "security.yes", false: "security.no"}[v]) }
	for i, s := range sums {
		if i > 0 {
			b.WriteString("\n")
		}
		kind := s.Kind
		switch s.Kind {
		case "certificado":
			kind = m("security.pki.kind.certificate")
		case "CSR":
			kind = m("security.pki.kind.csr")
		}
		fmt.Fprintf(&b, "%s: %s\n", kind, s.Subject)
		line := func(k, v string) {
			if v != "" {
				fmt.Fprintf(&b, "  %-16s %s\n", m("security.pki.label."+k), v)
			}
		}
		line("issuer", s.Issuer)
		line("serial", s.Serial)
		if s.NotAfter != "" {
			line("validity", i18n.Msg(loc, "security.pki.validity", i18n.A("from", s.NotBefore, "to", s.NotAfter, "days", s.DaysLeft)))
		}
		line("key", s.KeyType)
		line("signature", s.SigAlg)
		line("san", strings.Join(s.SANs, ", "))
		line("key_usage", strings.Join(s.KeyUsage, ", "))
		line("ext_key_usage", strings.Join(s.ExtKeyUsage, ", "))
		if s.IsCA {
			line("ca", yesNo(true))
		}
		if s.Kind == "CSR" {
			line("sig_valid", yesNo(s.SignatureValid))
		}
		line("sha1", s.SHA1)
		line("sha256", s.SHA256)
		for j, w := range s.Warnings {
			if j < len(s.WarnItems) {
				w = s.WarnItems[j].In(loc)
			}
			fmt.Fprintf(&b, "  ! %s\n", w)
		}
	}
	return b.String()
}
