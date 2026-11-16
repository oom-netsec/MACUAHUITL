package mask_test

import "testing"

// M₂ solo actúa sobre comandos: el texto entre comillas de la configuración impresa y de los avisos que no citan un
// comando queda exactamente como en la v0.6.5 (sin tapar de más).
func TestComillasDeConfigImpresaIgualAV065(t *testing.T) {
	lineas := []string{
		`snmp-server location "Site A key closet"`,
		`snmp-server contact "NOC text 555-1234"`,
		`% Incomplete command "key " at '^' marker.`,
		` action 1.0 syslog msg "key rotation done for peer 10.1.1.1"`,
		`event manager applet X ; action 1 syslog msg "password policy text ok"`,
		`banner motd "Authorized key holders only"`,
	}
	for _, plat := range []string{"ios-xe", "nx-os", "asa"} {
		for _, l := range lineas {
			for n, f := range map[string]func(im impl) string{
				"Apply":  func(im impl) string { return im.apply(plat, l+"\n") },
				"Stream": func(im impl) string { return im.stream(plat, l+"\n") },
				"terminal": func(im impl) string {
					return sesion(im, []ev{{false, "R1#"}, {true, "show run\r"}, {false, "show run\r\n" + l + "\r\nR1#"}}, 9)
				},
			} {
				if a, b := f(nuevo), f(viejo); a != b {
					t.Errorf("[%s %s] %q\n  nueva:  %q\n  v0.6.5: %q", plat, n, l, a, b)
				}
			}
		}
	}
}
