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
	validos := map[string]string{"mac": "aabb.ccdd.eeff", "ap": "AP-1", "wlan": "10", "interface": "Gi1/0/1", "ip": "10.0.0.1", "vrf": "common:default", "vnid": "2850817"}
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

// En nx-os los leaf ACI pasan la línea a bash en un shell persistente: los paréntesis podrían definir una función que
// se ejecutaría en el siguiente show, las llaves con «,» o «..» se expanden y esquivan las listas de tokens, y las
// comillas en los argumentos del show esquivan las comprobaciones de palabras («"binary"»). Los marcadores de datos
// ({interface}) y las comillas de un filtro tras «|» siguen valiendo.
func TestDenyNXOSParentesisLlavesYComillas(t *testing.T) {
	for _, cmd := range []string{
		"show version() { true; }", "show (x)", "show version | egrep \"(a|b)\"",
		"show tech-support {binary,x}", "show {a..b}", "show version {", "show version }",
		"show tech-support \"binary\"", "show \"version\"",
	} {
		if err := CheckDenied("nx-os", cmd); err == nil {
			t.Errorf("nx-os %q: no se rechazó", cmd)
		}
	}
	for _, cmd := range []string{
		"show interface {interface}", "show logging last 200 | egrep \"LACP|PORT-CHANNEL\"", "dir bootflash:",
		"show ip route vrf {vrf} | include {ip}",
	} {
		if err := CheckDenied("nx-os", cmd); err != nil {
			t.Errorf("nx-os %q: %v", cmd, err)
		}
	}
}

// «?» pide ayuda al equipo en la terminal interactiva: quita el signo y conserva el texto, así que corre otro comando.
func TestDenyInterrogacionEnTodasLasPlataformas(t *testing.T) {
	casos := map[string][]string{
		"ios":      {"show clock t?o-file flash:a"},
		"ios-xe":   {"show clock t?o-file flash:a"},
		"wlc-9800": {"show clock t?o-file flash:a"},
		"cat9k":    {"show clock t?o-file flash:a"},
		"asa":      {"show tech-support f?ile disk0:a"},
		"ftd":      {"show tech-support f?ile disk0:a"},
		"nx-os":    {"show tech-support bi?nary"},
	}
	for plat, cmds := range casos {
		for _, cmd := range cmds {
			if err := CheckDenied(plat, cmd); err == nil {
				t.Errorf("%s %q: no se rechazó", plat, cmd)
			}
		}
	}
}

func TestDenyTracerouteIOSTopes(t *testing.T) {
	for _, cmd := range []string{"traceroute 8.8.8.8 ttl 1 255 probe 10 timeout 10", "traceroute 8.8.8.8 ttl 1 31", "traceroute 8.8.8.8 probe 6"} {
		if CheckDenied("ios", cmd) == nil {
			t.Errorf("%q: no se rechazó", cmd)
		}
	}
	if err := CheckDenied("ios", "traceroute 8.8.8.8 ttl 1 30 probe 5 timeout 10"); err != nil {
		t.Errorf("en el tope: %v", err)
	}
}

// En nx-os (bash en los leaf ACI) «*» y «[» fuera de comillas se expanden tras la validación.
func TestDenyNXOSComodinesFueraDeComillas(t *testing.T) {
	for _, cmd := range []string{"show clock | grep *", "show clock | grep [a-z]", "show interface eth1/*", "show clock | grep a*"} {
		if CheckDenied("nx-os", cmd) == nil {
			t.Errorf("%q: no se rechazó", cmd)
		}
	}
	for _, cmd := range []string{`show clock | grep "a.*b"`, `show clock | egrep "[0-9]+"`} {
		if err := CheckDenied("nx-os", cmd); err != nil {
			t.Errorf("%q: %v", cmd, err)
		}
	}
}

// Un Nexus mal marcado como IOS: tras el segundo «|» también se rechazan estos comandos.
func TestDenyShellTokensAmpliados(t *testing.T) {
	for _, w := range []string{"sort -o a", "uniq", "cp a b", "mv a b", "rm a", "dd if=a", "sh", "ln a b", "chmod 777 a"} {
		if CheckDenied("ios", "show clock | include x | "+w) == nil {
			t.Errorf("| %s: no se rechazó", w)
		}
	}
}
