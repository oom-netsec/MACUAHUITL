package playbook

import (
	"strings"
	"testing"
)

var plataformasDeny = []string{"ios", "ios-xe", "nx-os", "asa", "ftd", "wlc-9800", "wlc-aireos"}

// «&», «<» y «||» los interpreta bash en la CLI de los leaf ACI: se rechazan en todas las plataformas.
func TestDenyMetacaracteresDeShell(t *testing.T) {
	for _, plat := range plataformasDeny {
		for _, cmd := range []string{
			"show version && reload", "show version & ", "show version || reload", "show version < /etc/passwd",
			"show version | include a||b", "show run | i a&b",
		} {
			if err := CheckDenied(plat, cmd); err == nil {
				t.Errorf("%s %q: no se rechazó", plat, cmd)
			}
		}
	}
}

// Un «|» suelto no se confunde con «||»: lo de hoy sigue pasando.
func TestDenyUnPipeSigueIgual(t *testing.T) {
	if err := CheckDenied("ios-xe", "show run | include a|b"); err != nil {
		t.Errorf("alternancia con un solo pipe: %v", err)
	}
}

// Cada tipo de dato rechaza todo carácter que bash o el equipo interpretarían, y lo que acepta pasa CheckDenied.
func TestTiposDeDatoRechazanMetacaracteres(t *testing.T) {
	validos := map[string]string{"mac": "aabb.ccdd.eeff", "ap": "AP-1", "wlan": "10", "interface": "Gi1/0/1", "ip": "10.0.0.1"}
	malos := []string{" ", "'", "\"", "$", "`", ";", "&", "|", "<", ">", "(", ")", "\\", "\n"}
	for _, k := range ParamKinds {
		base, ok := validos[k]
		if !ok {
			t.Fatalf("tipo %q sin caso válido en la prueba", k)
		}
		if _, err := ValidateValue(k, base); err != nil {
			t.Fatalf("%s %q: %v", k, base, err)
		}
		for _, m := range malos {
			for _, v := range []string{base + m, m + base, base[:1] + m + base[1:], m} {
				if _, err := ValidateValue(k, v); err == nil {
					t.Errorf("%s aceptó %q", k, v)
				}
			}
		}
	}
}

// {vrf} con forma tenant:vrf va como «interface»; {vnid} como «ap» (entero sin tope).
func TestDatosACI(t *testing.T) {
	for _, c := range []struct{ kind, v string }{{"interface", "tenant1:vrf_a"}, {"interface", "t-1:v.2"}, {"ap", "15000"}} {
		if _, err := ValidateValue(c.kind, c.v); err != nil {
			t.Errorf("%s %q: %v", c.kind, c.v, err)
		}
	}
	p := Playbook{Platform: "ios", Params: []Param{{"vrf", "interface"}, {"vnid", "ap"}}, Commands: []Command{{Text: "show x {vrf} {vnid} | include {vnid}"}}}
	out, err := p.Expand(map[string]string{"vrf": "t1:v1", "vnid": "15000"})
	if err != nil || !strings.Contains(out[0].Text, "t1:v1 15000") {
		t.Fatalf("%v %v", out, err)
	}
	if _, err := p.Expand(map[string]string{"vrf": "t1:v1&x", "vnid": "1"}); err == nil {
		t.Error("vrf con & aceptado")
	}
}

// En nx-os (los leaf ACI corren como nx-os y su CLI pasa por bash) se rechazan además «$», «!», «\» y «'»; en las demás
// plataformas siguen valiendo como parte de un patrón (^…$, ^!).
func TestDenyExpansionDeShellEnNXOS(t *testing.T) {
	for _, cmd := range []string{
		"show version $HOME", "show version | include ${x}", "show version !!", "show version | include !-1",
		"show version | include a\\|b", "show version 'x'", "show version | include 'a|b'",
	} {
		if err := CheckDenied("nx-os", cmd); err == nil {
			t.Errorf("nx-os %q: no se rechazó", cmd)
		}
	}
	for _, c := range [][2]string{{"ios-xe", "show running-config | include ^interface.*$"}, {"ios", "show running-config | include ^!"}, {"asa", "show version | grep -v ^$"}} {
		if err := CheckDenied(c[0], c[1]); err != nil {
			t.Errorf("%s %q: %v", c[0], c[1], err)
		}
	}
}
