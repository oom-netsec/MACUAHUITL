package i18n

import "testing"

// En inglés el singular va con n=1; el español no cambia con n.
func TestPluralesEnIngles(t *testing.T) {
	for _, c := range []struct {
		code string
		args Args
		en1  string
		en2  string
		es1  string
	}{
		{"pcap.text.counts", A("packets", 1, "bytes", 1), "1 packet  1 byte", "2 packets  2 bytes", "1 paquetes  1 bytes"},
		{"pcap.text.failed_flow", A("client", "a", "server", "b", "attempts", 1), "a → b  (1 attempt)", "a → b  (2 attempts)", "a → b  (1 intentos)"},
		{"security.pki.validity", A("from", "x", "to", "y", "days", 1), "x → y (1 day)", "x → y (2 days)", "x → y (1 días)"},
		{"security.pki.warn.expires_soon", A("days", 1), "expires in 1 day", "expires in 2 days", "vence en 1 días"},
	} {
		two := Args{}
		for k, v := range c.args {
			two[k] = v
		}
		for _, k := range []string{"packets", "bytes", "attempts", "days"} {
			if _, ok := two[k]; ok {
				two[k] = "2"
			}
		}
		if got := Msg(En, c.code, c.args); got != c.en1 {
			t.Errorf("%s n=1: %q", c.code, got)
		}
		if got := Msg(En, c.code, two); got != c.en2 {
			t.Errorf("%s n=2: %q", c.code, got)
		}
		if got := Msg(Es, c.code, c.args); got != c.es1 {
			t.Errorf("%s es: %q", c.code, got)
		}
	}
}
