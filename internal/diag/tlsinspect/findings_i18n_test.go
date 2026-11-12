package tlsinspect

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"
)

// newCAAt es newCA con la validez centrada en una hora fija.
func newCAAt(t *testing.T, now time.Time) (*x509.Certificate, any, *x509.CertPool) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CA de laboratorio"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return c, k, pool
}

// escenariosTLS inspecciona servidores de juguete con una hora fija y devuelve lo que traduce la fase 30c:
// los hallazgos y el error de verificación.
func escenariosTLS(t *testing.T) map[string]Report {
	t.Helper()
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	out := map[string]Report{}
	run := func(name, sni string, roots *x509.CertPool, ca *x509.Certificate, key any, s certSpec) {
		port := serve(t, issue(t, ca, key, s), tls.VersionTLS12, tls.VersionTLS13)
		r, err := Inspect(context.Background(), dial, "127.0.0.1", port, sni, Options{Roots: roots, Now: func() time.Time { return now }})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = r
	}
	ca, key, pool := newCAAt(t, now)
	spec := func(name string, from, to time.Time, rsa int) certSpec {
		return certSpec{name: name, notBefore: from, notAfter: to, rsaBits: rsa}
	}
	run("vencido", "wlc.lab", pool, ca, key, spec("wlc.lab", now.Add(-30*day), now.Add(-day), 0))
	run("aun-no-valido", "wlc.lab", pool, ca, key, spec("wlc.lab", now.Add(10*day), now.Add(100*day), 0))
	run("vence-pronto", "wlc.lab", pool, ca, key, spec("wlc.lab", now.Add(-day), now.Add(10*day), 0))
	run("nombre", "ise.lab", pool, ca, key, spec("otro.lab", now.Add(-day), now.Add(100*day), 0))
	run("llave-debil", "ise.lab", pool, ca, key, spec("ise.lab", now.Add(-day), now.Add(100*day), 1024))
	run("autofirmado", "fmc.lab", pool, nil, nil, certSpec{name: "fmc.lab", notBefore: now.Add(-day), notAfter: now.Add(100 * day), selfSign: true})
	run("cadena-incompleta", "ise.lab", x509.NewCertPool(), ca, key, spec("ise.lab", now.Add(-day), now.Add(100*day), 0))
	run("ok", "ise.lab", pool, ca, key, spec("ise.lab", now.Add(-day), now.Add(100*day), 0))
	return out
}

func viewTLS(r Report) map[string]any {
	return map[string]any{"findings": r.Findings, "verifyError": r.VerifyError, "daysLeft": r.DaysLeft}
}

// Regresión: los hallazgos en español son los de antes del catálogo (UPDATE_GOLDEN=1 lo reescribe).
func TestFindingsEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for n, r := range escenariosTLS(t) {
		b, _ := json.Marshal(viewTLS(r))
		got[n] = string(b)
	}
	const file = "testdata/findings_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for n, g := range got {
		if g != want[n] {
			t.Errorf("%s cambió:\n got: %s\nwant: %s", n, g, want[n])
		}
	}
}

// Con en el detalle sale en inglés y coincide con el catálogo; VerifyCode clasifica el error del sistema.
func TestFindingsEnYCodigoDeVerificacion(t *testing.T) {
	wantCode := map[string]string{"vencido": "expired", "aun-no-valido": "not_yet_valid", "nombre": "hostname", "autofirmado": "unknown_authority",
		"cadena-incompleta": "unknown_authority", "ok": "", "llave-debil": "", "vence-pronto": ""}
	n := 0
	for name, r := range escenariosTLS(t) {
		if r.VerifyCode != wantCode[name] {
			t.Errorf("%s: VerifyCode %q, esperaba %q", name, r.VerifyCode, wantCode[name])
		}
		en := r.In("en")
		for i, f := range en.Findings {
			n++
			if f.Detail != r.Findings[i].Text.In("en") || f.Detail == r.Findings[i].Detail || f.Text.Key == "" {
				t.Errorf("%s: %q sin traducir", name, f.Detail)
			}
		}
		if en.VerifyError != r.VerifyError {
			t.Errorf("%s: VerifyError cambió", name)
		}
	}
	if n < 6 {
		t.Errorf("solo %d hallazgos", n)
	}
}

// In(es) no cambia nada: el servicio la usa siempre, así que el JSON en español debe quedar igual (nulo sigue nulo).
func TestInEspanolEsIdentidad(t *testing.T) {
	for n, r := range escenariosTLS(t) {
		a, _ := json.Marshal(r)
		b, _ := json.Marshal(r.In("es"))
		if string(a) != string(b) {
			t.Errorf("%s: In(es) cambia el JSON:\n%s\n%s", n, a, b)
		}
	}
}
