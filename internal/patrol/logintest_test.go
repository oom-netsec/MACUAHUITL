package patrol

import "testing"

// La clave de huellas aceptadas coincide con el host:puerto que muestra el Login Test, también con IPv6 no canónica.
func TestHostKeyIDCoincideConElLoginTest(t *testing.T) {
	for _, a := range []string{"2001:db8:0::1", "2001:0db8::1", "2001:DB8::1", "10.0.0.1", "10.0.0.1"} {
		tg := Target{Address: a, Port: 22}
		if HostKeyID(tg) != Hostport(tg) {
			t.Errorf("%s: HostKeyID %q, Login Test %q", a, HostKeyID(tg), Hostport(tg))
		}
	}
}
