package mask_test

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

const marcaRecorte = "[\u2026 output truncated: 67108864 bytes omitted \u2026]"

// Los diez bloques con valor en la línea siguiente a la marca de recorte del driver.
var bloquesRecorte = []struct{ plat, abre, valor, linea string }{
	{"ios-xe", "tacacs server T", "Zq9Lm4Xw7Rt2", " key Zq9Lm4Xw7Rt2"},
	{"ios-xe", "radius server R", "Zq9Lm4Xw7Rt2", " key Zq9Lm4Xw7Rt2"},
	{"ios-xe", "line vty 0 4", "Zq9Lm4Xw7Rt2", " password Zq9Lm4Xw7Rt2"},
	{"ios-xe", "crypto pki trustpoint TP", "Zq9Lm4Xw7Rt2", " password Zq9Lm4Xw7Rt2"},
	{"ios-xe", "dot1x credentials D", "Zq9Lm4Xw7Rt2", " password Zq9Lm4Xw7Rt2"},
	{"ios-xe", "license smart", "Zq9Lm4Xw7Rt2", " token Zq9Lm4Xw7Rt2"},
	{"ios-xe", "parameter-map type umbrella global", "Zq9Lm4Xw7Rt2", " token Zq9Lm4Xw7Rt2"},
	{"ios-xe", "crypto isakmp client configuration group G", "Zq9Lm4Xw7Rt2", " key Zq9Lm4Xw7Rt2"},
	{"ios-xe", "cluster group C", "Zq9Lm4Xw7Rt2", " key Zq9Lm4Xw7Rt2"},
	{"asa", "aaa-server S protocol tacacs+", "Zq9Lm4Xw7Rt2", " key Zq9Lm4Xw7Rt2"},
}

// La marca del recorte (línea fija del driver) no es una línea de nivel superior: no cambia el estado del enmascarado.
func TestMarcaRecorteNoRompeBloque(t *testing.T) {
	for _, b := range bloquesRecorte {
		con := b.abre + "\n x\n" + marcaRecorte + "\n" + b.linea + "\n!\n"
		sin := b.abre + "\n x\n" + b.linea + "\n!\n"
		got, _ := mask.Apply(b.plat, con)
		want, _ := mask.Apply(b.plat, sin)
		want = strings.Replace(want, " x\n", " x\n"+marcaRecorte+"\n", 1)
		if got != want {
			t.Errorf("%s:\n got %q\nwant %q", b.abre, got, want)
		}
		for g, n := range visibles4(got, b.valor) {
			if n > 0 {
				t.Errorf("%s: se ve el 4-grama %q", b.abre, g)
			}
		}
	}
}

func TestMarcaRecorteNoCortaPEM(t *testing.T) {
	in := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAZq9Lm4Xw7Rt2\n" + marcaRecorte + "\nQWxhZGRpbjpvcGVuIHNlc2FtZQ==\n-----END RSA PRIVATE KEY-----\nhostname R1\n"
	got, _ := mask.Apply("ios-xe", in)
	if strings.Contains(got, "QWxhZGRpbjp") || !strings.Contains(got, "hostname R1") {
		t.Fatalf("PEM: %q", got)
	}
}

// Solo la marca exacta es transparente: una línea parecida sigue el camino de S1 (nivel superior, corta el bloque).
func TestMarcaRecorteImitadaNoEsTransparente(t *testing.T) {
	in := "tacacs server T\n[\u2026 output truncated: 5 bytes omitted \u2026] x\n key Zq9Lm4Xw7Rt2\n"
	want, _ := mask.ApplyPlain("ios-xe", in)
	if got, _ := mask.Apply("ios-xe", in); got != want {
		t.Fatalf("%q != %q", got, want)
	}
}
