package assist

import (
	"strings"
	"testing"
)

// B1: una línea rechazada cuyo secreto va tras una palabra que solo es secreto dentro de su bloque (token, key) no sale en claro.
func TestRedactSinBloqueTapaLoCitado(t *testing.T) {
	for _, l := range []string{" token UMBTOK", "token UMBTOK2", " key RADKEY1", "  password 0 PWBLK1"} {
		if got := redact(l); strings.Contains(got, "UMBTOK") || strings.Contains(got, "RADKEY1") || strings.Contains(got, "PWBLK1") {
			t.Errorf("redact(%q) = %q", l, got)
		}
	}
	if got := redact(" description enlace"); got != " description enlace" && got != "description enlace" {
		t.Errorf("cambió una línea sin secreto: %q", got)
	}
}
