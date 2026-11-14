package playbook

import "testing"

// El destino de ping y traceroute es igual de estricto en todas las plataformas: IPv4 de 4 octetos decimales, IPv6
// válida o un nombre con letras en la última etiqueta; «224.1» (multicast), «4294967295», «0xffffffff» o «127.1» los
// resuelve el equipo como otra dirección.
func TestDestinoDeSondaEstricto(t *testing.T) {
	malos := []string{"224.1", "4294967295", "0xffffffff", "127.1", "0177.0.0.1", "10.1", "255.255.255.255.", "10.1.1.1.", "0xff.1.1.1", "224.0.0.1", "0.0.0.0", "255.255.255.255"}
	buenos := []string{"10.1.1.1", "2001:db8::1", "host1.dc1", "sw01", "fw-01.corp.example.com", "fw-01.corp.example.com.", "{ip}"}
	for _, p := range []string{"ios", "ios-xe", "wlc-9800", "nx-os", "asa", "ftd", "ise"} {
		for _, verbo := range []string{"ping", "traceroute"} {
			for _, d := range malos {
				if err := CheckDenied(p, verbo+" "+d); err == nil {
					t.Errorf("%s «%s %s»: se aceptó", p, verbo, d)
				}
			}
			for _, d := range buenos {
				if (p == "asa" || p == "ftd") && d == "sw01" {
					continue // en ASA y FTD una palabra suelta sin punto se rechaza desde antes (indistinguible de una interfaz)
				}
				if err := CheckDenied(p, verbo+" "+d); err != nil {
					t.Errorf("%s «%s %s»: %v", p, verbo, d, err)
				}
			}
		}
	}
}
