package field

import "testing"

// Una IP sola toma el puerto por omisión del protocolo (TFTP 69, HTTP 80); una dirección con puerto se respeta.
// Se prueba sin abrir sockets: la prueba de integración de core usa un puerto libre para no chocar con otra suite.
func TestServeAddrPuertoPorOmision(t *testing.T) {
	for _, c := range []struct{ proto, in, want string }{
		{"tftp", "127.0.0.1", "127.0.0.1:69"},
		{"http", "127.0.0.1", "127.0.0.1:80"},
		{"tftp", "::1", "[::1]:69"},
		{"tftp", "[::1]", "[::1]:69"},
		{"tftp", "127.0.0.1:0", "127.0.0.1:0"},
		{"http", "127.0.0.1:9090", "127.0.0.1:9090"},
		{"tftp", "fe80::1%eth0", "[fe80::1%eth0]:69"},
		{"tftp", "[fe80::1%eth0]:7", "[fe80::1%eth0]:7"},
		{"tftp", "[::1]:7000", "[::1]:7000"},
		{"tftp", "localhost", "localhost"},
		{"tftp", "", ""},
	} {
		got, ok := serveAddr(c.proto, c.in)
		if !ok || got != c.want {
			t.Errorf("serveAddr(%q, %q) = %q, %v; quiero %q", c.proto, c.in, got, ok, c.want)
		}
	}
	if _, ok := serveAddr("ftp", "127.0.0.1"); ok {
		t.Error("ftp no se publica: debe dar ok=false")
	}
}

func TestPuertosPorOmision(t *testing.T) {
	if p := defaultServePort; p["tftp"] != 69 || p["http"] != 80 {
		t.Errorf("%v", p)
	}
}
