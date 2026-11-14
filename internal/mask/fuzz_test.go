package mask

import (
	"strings"
	"testing"
)

var fuzzPlatforms = []string{"ios", "ios-xe", "nx-os", "asa", "ftd", "aireos", "ise", ""}

const fuzzSeed = "SEMILLA7"

func FuzzApply(f *testing.F) {
	f.Add(byte(1), "username bob password 0 hola\n")
	f.Add(byte(3), "username bob password 0 open version two\n")
	f.Add(byte(0), "line vty 0 4\n password 0 my pw\n")
	f.Add(byte(1), "dot1x credentials SUP\n username host1\n password 0 Secreta\n!\ninterface Gi1\n description password x\n")
	f.Add(byte(2), "snmp-server community public group network-admin\n")
	f.Add(byte(1), "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n")
	f.Add(byte(4), "")
	f.Fuzz(func(t *testing.T, p byte, text string) {
		plat := fuzzPlatforms[int(p)%len(fuzzPlatforms)]
		out, _ := Apply(plat, text)
		// Idempotencia: lo ya enmascarado no cambia al pasar otra vez.
		if again, _ := Apply(plat, out); again != out {
			t.Fatalf("no idempotente (%q)\n1: %q\n2: %q", plat, out, again)
		}
		// Un secreto sembrado en forma de regla no sale en claro, sea cual sea el texto previo.
		if strings.Contains(text, fuzzSeed) {
			return
		}
		sec, _ := Apply(plat, text+"\nusername u password 0 "+fuzzSeed+"\n")
		if strings.Contains(sec, fuzzSeed) {
			t.Fatalf("SEGURIDAD: el secreto sembrado se filtró (%q): %q", plat, sec)
		}
	})
}

// FuzzStream: Line en secuencia con trozos arbitrarios; ni pánico ni filtración del secreto sembrado.
func FuzzStream(f *testing.F) {
	f.Add(byte(1), "username bob password 0 hola\nline vty 0 4\n password 0 x\n")
	f.Add(byte(3), "a\r\nb\n\n")
	f.Fuzz(func(t *testing.T, p byte, text string) {
		if strings.Contains(text, fuzzSeed) {
			return
		}
		st := Stream{Platform: fuzzPlatforms[int(p)%len(fuzzPlatforms)], MaxSkip: 50}
		var out strings.Builder
		for _, raw := range strings.SplitAfter(text+"\nusername u password 0 "+fuzzSeed+"\n", "\n") {
			if l, ok := st.Line(raw); ok {
				out.WriteString(l)
			}
		}
		if strings.Contains(out.String(), fuzzSeed) {
			t.Fatalf("SEGURIDAD: secreto sembrado filtrado por Stream: %q", out.String())
		}
	})
}
