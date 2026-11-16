package mask_test

import (
	"fmt"
	"github.com/oom-netsec/MACUAHUITL/internal/mask/internal/ref065"
	"regexp"
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

var semilla = regexp.MustCompile(`Zq\d{5}`)

// visibles: cuántas semillas (Zq00000) se ven en out.
func visibles(out string) int { return len(semilla.FindAllString(out, -1)) }

// La marca cierra la tabla de communities, como en la v0.6.5 (ref065 la ve como una línea sin forma de fila): lo que
// sigue a la marca se enmascara por sus reglas y nunca se ve más que con ref065 sobre el mismo texto.
func TestMarcaRecorteCierraLaTablaSNMP(t *testing.T) {
	head := "Community            Group / Access      context    acl_filter\n---------            --------------      -------    ----------\nSecretComm           network-admin\n"
	for _, plat := range []string{"nx-os", "ios-xe"} {
		for _, cola := range []string{"enable password Zq00001\n", "tacacs server T\n key Zq00002\n"} {
			in := head + marcaRecorte + "\n" + cola
			n, _ := mask.Apply(plat, in)
			o, _ := ref065.Apply(plat, in)
			if visibles(n) > visibles(o) || visibles(n) != 0 {
				t.Errorf("%s:\n nueva %q\n ref   %q", plat, n, o)
			}
		}
	}
}

// nuncaMas: la salida nueva de con (el texto con marca) no muestra más semillas que ref065 con la marca ni que ref065 sin ella.
func nuncaMas(plat, con, sin string) (bool, string) {
	n, _ := mask.Apply(plat, con)
	o, _ := ref065.Apply(plat, con)
	s, _ := ref065.Apply(plat, sin)
	return visibles(n) <= visibles(o) && visibles(n) <= visibles(s), fmt.Sprintf("\n nueva %q\n ref con %q\n ref sin %q", n, o, s)
}

// La marca dentro de una tabla isakmp: la fila siguiente se tapa (ref065 cuenta la marca como fila y la tabla sigue abierta).
func TestMarcaRecorteEnTablaIsakmp(t *testing.T) {
	in := "Keyring      Hostname/Address      Preshared Key\n\ndefault      10.1.1.1              Zq00005\n" + marcaRecorte + "\ndefault      10.1.1.2              Zq00006\n"
	for _, plat := range []string{"ios-xe", "nx-os", "asa"} {
		n, _ := mask.Apply(plat, in)
		if visibles(n) != 0 {
			t.Errorf("%s: %q", plat, n)
		}
	}
}

// Con la marca entre cada par de entradas de la propiedad diferencial y dentro de cada tabla SNMP/isakmp, nunca se ve
// más que con ref065 con la marca ni que con ref065 sin ella.
func TestMarcaRecorteNuncaMuestraMas(t *testing.T) {
	cmds, plats := casosDif()
	heads := []struct{ head, fila string }{
		{"Community            Group / Access      context    acl_filter\n---------            --------------      -------    ----------\n", "SecretComm           network-admin\n"},
		{"Host                            Port Version  Level  Type   SecName\n-------------------------------------------------------------------\n", "10.1.1.1                        162  v2c      noauth trap   Zq00007\n"},
		{"Keyring      Hostname/Address      Preshared Key\n\n", "default      10.1.1.1              Zq00005\n"},
	}
	malos := 0
	check := func(plat, con, sin string) {
		if ok, det := nuncaMas(plat, con, sin); !ok {
			if malos++; malos <= 10 {
				t.Errorf("(%s) %q%s", plat, con, det)
			}
		}
	}
	for i := 0; i+1 < len(cmds); i++ {
		check(plats[i], cmds[i]+"\n"+marcaRecorte+"\n"+cmds[i+1]+"\n", cmds[i]+"\n"+cmds[i+1]+"\n")
		h := heads[i%len(heads)]
		for _, plat := range []string{plats[i], "nx-os", "ios-xe", "asa"} {
			check(plat, h.head+h.fila+marcaRecorte+"\n"+cmds[i]+"\n"+h.fila+cmds[i+1]+"\n", h.head+h.fila+cmds[i]+"\n"+h.fila+cmds[i+1]+"\n")
		}
	}
	if malos > 10 {
		t.Errorf("%d violaciones en total", malos)
	}
}
