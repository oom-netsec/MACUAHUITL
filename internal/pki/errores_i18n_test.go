package pki

import (
	"crypto"
	"regexp"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

// erroresPKI provoca cada error de validación y de formato con entradas inválidas.
func erroresPKI(t *testing.T) map[string]error {
	t.Helper()
	key, _ := GenerateKey("p256")
	other, _ := GenerateKey("p256")
	ca, _ := InitCA(key, "Lab CA", 20, now)
	leafKey, _ := GenerateKey("p256")
	csr, _ := CreateCSR(leafKey, CSRRequest{Subject: Subject{CN: "a.lab"}})
	crt, _ := Sign(ca, key, csr, "server", 30, now)
	sealed, _ := SealKey(key, []byte("pw"), params)
	var signer crypto.Signer = other
	e := map[string]error{}
	put := func(n string, err error) { e[n] = err }
	csrErr := func(r CSRRequest) error { _, err := CreateCSR(key, r); return err }
	put("alg", func() error { _, err := GenerateKey("dsa"); return err }())
	put("sealed-tipo", func() error { _, err := OpenKey([]byte("x"), nil); return err }())
	put("sealed-clave", func() error { _, err := OpenKey(sealed, []byte("mal")); return err }())
	put("csr-cn", csrErr(CSRRequest{}))
	put("csr-pais", csrErr(CSRRequest{Subject: Subject{CN: "a", C: "MEX"}}))
	put("csr-ip", csrErr(CSRRequest{Subject: Subject{CN: "a"}, IPs: []string{"x.y"}}))
	put("ca-nombre", func() error { _, err := InitCA(key, " ", 20, now); return err }())
	put("ca-dias", func() error { _, err := InitCA(key, "a", 0, now); return err }())
	put("sign-pem", func() error { _, err := Sign([]byte("x"), key, csr, "server", 30, now); return err }())
	put("sign-noca", func() error { _, err := Sign(crt, key, csr, "server", 30, now); return err }())
	put("sign-perfil", func() error { _, err := Sign(ca, key, csr, "raro", 30, now); return err }())
	put("sign-csr", func() error { _, err := Sign(ca, key, []byte("x"), "server", 30, now); return err }())
	put("sign-csr-malo", func() error {
		_, err := Sign(ca, key, []byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"), "server", 30, now)
		return err
	}())
	put("export-llave", func() error { _, err := Export("pem", crt, nil, signer, ""); return err }())
	put("export-p12", func() error { _, err := Export("p12", crt, nil, nil, ""); return err }())
	put("export-formato", func() error { _, err := Export("zip", crt, nil, nil, ""); return err }())
	put("export-cadena", func() error {
		_, err := Export("pem", crt, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), nil, "")
		return err
	}())
	put("decode-cert", func() error {
		_, err := Decode([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), now)
		return err
	}())
	put("decode-csr", func() error {
		_, err := Decode([]byte("-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"), now)
		return err
	}())
	put("decode-bloque", func() error {
		_, err := Decode([]byte("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"), now)
		return err
	}())
	put("decode-nada", func() error { _, err := Decode([]byte("hola"), now); return err }())
	return e
}

func TestErroresPKIEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for n, err := range erroresPKI(t) {
		if err == nil {
			t.Fatalf("%s: debía fallar", n)
		}
		got[n] = err.Error()
	}
	i18ntest.Golden(t, "testdata/errores_es.golden.json", got)
}

var espanol = regexp.MustCompile(`(?i)[áéíóúñ¿]|\b(falta|llave|certificado|inválid|desconocid|soportad|dirección|resolver|necesita|corresponde|cadena|bloque|esperaba|formato|perfil|algoritmo|países?)\b`)

func TestErroresPKIEnSinEspanol(t *testing.T) {
	for n, err := range erroresPKI(t) {
		if s := i18n.In("en", err); espanol.MatchString(s) {
			t.Errorf("%s: queda español: %q", n, s)
		}
	}
}
