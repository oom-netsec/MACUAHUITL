package assist

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Fase 30e: la etiqueta de lo que se valida («red», «siguiente salto»...) sale en el idioma del error.
func TestEtiquetaDeDireccionEnElIdioma(t *testing.T) {
	cases := []struct{ key, es, en string }{
		{"assist.what.network", "red", "network"},
		{"assist.what.next_hop", "siguiente salto", "next hop"},
		{"assist.what.loopback", "loopback", "loopback"},
		{"assist.what.helper", "helper", "helper"},
		{"assist.what.ntp_server", "servidor NTP", "NTP server"},
		{"assist.what.syslog_dest", "destino de syslog", "syslog destination"},
	}
	for _, c := range cases {
		err := unicastIPv4(c.key, "0.0.0.0")
		if got := err.Error(); got != c.es+": 0.0.0.0 no es una dirección unicast utilizable" {
			t.Errorf("es: %q", got)
		}
		if got := i18n.English(err); got != c.en+": 0.0.0.0 is not a usable unicast address" {
			t.Errorf("en: %q", got)
		}
		err = unicastIPv4(c.key, "x")
		if got := i18n.English(err); !strings.HasPrefix(got, c.en+": invalid IPv4") {
			t.Errorf("en inválida: %q", got)
		}
	}
}
