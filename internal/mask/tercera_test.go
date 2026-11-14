package mask

import (
	"strings"
	"testing"
)

// Tras show snmp community sin línea en blanco, la config que sigue no es una fila: no pierde su primera palabra.
// Las filas reales (con o sin columnas alineadas) sí se tapan.
func TestTablaDeComunidadesNoTragaConfigAjena(t *testing.T) {
	in := strings.Join([]string{
		"Community            Group / Access      context    acl_filter",
		"---------            --------------      -------    ----------",
		"SECRETO-RO           network-operator",
		"pub network-operator",
		"hostname N9K",
		"interface Ethernet1/1",
		"  ip address 10.1.1.1/24",
		"  shutdown",
		"!",
		"Ethernet1/1",
	}, "\n") + "\n"
	got, _ := Apply("nx-os", in)
	for _, s := range []string{"SECRETO-RO", "\npub "} {
		if strings.Contains(got, s) {
			t.Errorf("quedó %q en claro:\n%s", s, got)
		}
	}
	for _, s := range []string{"hostname N9K", "interface Ethernet1/1", "  ip address 10.1.1.1/24", "  shutdown", "\nEthernet1/1"} {
		if !strings.Contains(got, s) {
			t.Errorf("se tapó de más %q:\n%s", s, got)
		}
	}
}

// Un puerto con ruta antes de una «@» no es una clave; una clave numérica sin ruta sí lo es.
func TestURLConPuertoNoEsClave(t *testing.T) {
	for in, want := range map[string]string{
		"https://srv:8443/api?u=me@x.com": "https://srv:8443/api?u=me@x.com",
		"ftp://user:1234@10.1.1.1/f":      "ftp://user:<MASKED:url-password>@10.1.1.1/f",
		"scp://u:Cl4/ve@h/":               "scp://u:<MASKED:url-password>@h/",
	} {
		if got, _ := Apply("ios-xe", in+"\n"); got != want+"\n" {
			t.Errorf("Apply(%q) = %q, want %q", in, got, want)
		}
	}
}
