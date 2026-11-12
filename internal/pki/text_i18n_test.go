package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

var hexy = regexp.MustCompile(`[0-9A-F]{12,}`)

// escenarios decodifica certificados y CSR que cubren todas las etiquetas y los avisos del informe.
func escenarios(t *testing.T) map[string][]Summary {
	t.Helper()
	out := map[string][]Summary{}
	dec := func(name string, pem []byte, at time.Time) {
		s, err := Decode(pem, at)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = s
	}
	caKey, _ := GenerateKey("p256")
	ca, _ := InitCA(caKey, "Lab CA", 20, now)
	dec("ca-vigente", ca, now)
	dec("ca-por-vencer", ca, now.Add(5*24*time.Hour))
	dec("ca-vencida", ca, now.Add(60*24*time.Hour))
	dec("ca-futura", ca, now.Add(-24*time.Hour))
	rk, _ := GenerateKey("rsa2048")
	csr, _ := CreateCSR(rk, CSRRequest{Subject: Subject{CN: "ise01.lab.local", O: "Lab", C: "MX"}, DNS: []string{"ise01.lab.local"}, IPs: []string{"10.0.0.10"}})
	dec("csr", csr, now)
	nosan, _ := CreateCSR(rk, CSRRequest{Subject: Subject{CN: "sin-san"}})
	dec("csr-sin-san", nosan, now)
	cert, err := Sign(ca, caKey, csr, "server", 365, now)
	if err != nil {
		t.Fatal(err)
	}
	dec("hoja", append(append([]byte{}, cert...), csr...), now)
	cert2, _ := Sign(ca, caKey, nosan, "client", 10, now)
	dec("hoja-sin-san", cert2, now)
	return out
}

func norm(s []Summary) map[string]string {
	b, _ := json.Marshal(s)
	return map[string]string{"json": hexy.ReplaceAllString(string(b), "X"), "text": hexy.ReplaceAllString(Text(s), "X")}
}

// Regresión: el texto en español del informe es el de antes del catálogo (UPDATE_GOLDEN=1 lo reescribe).
func TestTextoEspanolRegresion(t *testing.T) {
	got := map[string]map[string]string{}
	for n, s := range escenarios(t) {
		got[n] = norm(s)
	}
	const file = "testdata/text_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	for n, g := range got {
		for k, v := range g {
			if want[n][k] != v {
				t.Errorf("%s/%s cambió\n got: %s\nwant: %s", n, k, v, want[n][k])
			}
		}
	}
}

// Los avisos que los escenarios no alcanzan (llave RSA corta, firma con SHA-1) salen del catálogo en los dos idiomas.
func TestAvisosDeLlaveYFirma(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	s := Summary{Kind: "certificado", Subject: "CN=x", SigAlg: "SHA1-RSA", SANs: []string{"x"}}
	warnKey(&k.PublicKey, &s)
	if len(s.Warnings) != 2 || len(s.WarnItems) != 2 || s.Warnings[0] != "llave RSA de menos de 2048 bits: ISE y navegadores la rechazan" || s.Warnings[1] != "firma con SHA1-RSA: algoritmo obsoleto" {
		t.Fatalf("%v", s.Warnings)
	}
	if got := s.WarnItems[1].In("en"); got != "signature with SHA1-RSA: obsolete algorithm" {
		t.Error(got)
	}
	s.setKey(&k.PublicKey)
	if s.KeyAlg != "RSA" || s.KeyBits != 1024 {
		t.Errorf("%+v", s)
	}
	if LabWarning != i18n.Msg("es", "security.pki.lab_warning", nil) || LabWarning == "" {
		t.Error("el aviso de laboratorio no es el del catálogo")
	}
}
