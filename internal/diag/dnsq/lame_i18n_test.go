package dnsq

import (
	"errors"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// El error citado en «ns-lame» sale en el idioma pedido, sin mezclar la frase en inglés con un error en español.
func TestHallazgoNSLameSinMezcla(t *testing.T) {
	cod := i18n.New("dns.trace.err.no_servers", i18n.A("zone", "lab."))
	f := findingErr("error", "ns-lame", "dns.finding.ns_unreachable", cod, "name", "ns1", "ip", "192.0.2.1")
	if want := "ns1 (192.0.2.1) no responde: dnsq: no hay servidores para lab."; f.Detail != want {
		t.Errorf("es: %q", f.Detail)
	}
	if got, want := f.Text.In("en"), "ns1 (192.0.2.1) does not respond: dnsq: there are no servers for lab."; got != want {
		t.Errorf("en: %q", got)
	}
	g := findingErr("error", "ns-lame", "dns.finding.ns_unreachable", errors.New("i/o timeout"), "name", "ns1", "ip", "192.0.2.1")
	if g.Detail != "ns1 (192.0.2.1) no responde: i/o timeout" || g.Text.In("en") != "ns1 (192.0.2.1) does not respond: i/o timeout" {
		t.Errorf("sistema: %q / %q", g.Detail, g.Text.In("en"))
	}
}
