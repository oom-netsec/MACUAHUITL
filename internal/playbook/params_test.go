package playbook

import (
	"strings"
	"testing"
	"testing/fstest"
)

func loadOne(t *testing.T, y string) (Playbook, error) {
	t.Helper()
	pbs, err := Load(fstest.MapFS{"x.yaml": {Data: []byte(y)}})
	if err != nil {
		return Playbook{}, err
	}
	return pbs[0], nil
}

const withMAC = `id: cli
platform: wlc-9800
name: Cliente
params:
  - {name: mac, kind: mac}
commands:
  - cmd: show wireless client mac-address {mac} detail
`

func TestParamsLoad(t *testing.T) {
	p, err := loadOne(t, withMAC)
	if err != nil || len(p.Params) != 1 || p.Params[0] != (Param{"mac", "mac"}) {
		t.Fatalf("%v %+v", err, p.Params)
	}
	for name, y := range map[string]string{
		"sin declarar": strings.Replace(withMAC, "params:\n  - {name: mac, kind: mac}\n", "", 1),
		"sin usar":     strings.Replace(withMAC, "{mac} detail", "x detail", 1),
		"tipo malo":    strings.Replace(withMAC, "kind: mac", "kind: otro", 1),
		"nombre malo":  strings.Replace(strings.Replace(withMAC, "name: mac", "name: M-1", 1), "{mac}", "{M-1}", 1),
		"repetido":     strings.Replace(withMAC, "- {name: mac, kind: mac}", "- {name: mac, kind: mac}\n  - {name: mac, kind: ip}", 1),
		"en pre":       strings.Replace(withMAC, "commands:", "pre: [\"show clock {mac}\"]\ncommands:", 1),
	} {
		if _, err := loadOne(t, y); err == nil || !strings.Contains(err.Error(), "x.yaml") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExpand(t *testing.T) {
	p, _ := loadOne(t, withMAC)
	for _, v := range []string{"AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabb.ccdd.eeff", "AABBCCDDEEFF"} {
		c, err := p.Expand(map[string]string{"mac": v})
		if err != nil || c[0].Text != "show wireless client mac-address aabb.ccdd.eeff detail" {
			t.Errorf("%s: %v %v", v, err, c)
		}
	}
	for _, v := range []string{"", "aa:bb:cc:dd:ee:ff\nconf t", "aabb.ccdd.eeff | redirect flash:x", "aabb.ccdd.eeff; reload",
		"aabb.ccdd.eef", "a:a:b:b:c:c:d:d:e:e:f:f", "aabbccddeeff-----", "ａａbb.ccdd.eeff", strings.Repeat("a", 5000), "aabb.ccdd.eeff "} {
		if _, err := p.Expand(map[string]string{"mac": v}); err == nil {
			t.Errorf("aceptó %q", v)
		}
	}
	if _, err := p.Expand(nil); err == nil {
		t.Error("faltante aceptado")
	}
	if _, err := p.Expand(map[string]string{"mac": "aabb.ccdd.eeff", "otro": "x"}); err == nil {
		t.Error("desconocido aceptado")
	}
	// sin datos: idéntico a hoy
	q, _ := loadOne(t, "id: a\nplatform: ios-xe\nname: A\ncommands:\n  - cmd: show clock\n")
	if c, err := q.Expand(nil); err != nil || len(c) != 1 || c[0].Text != "show clock" {
		t.Error(err)
	}
}

func TestExpandKinds(t *testing.T) {
	ok := map[string][]string{"ap": {"AP-9120_1", "a.b-c"}, "interface": {"Gi1/0/11", "Tw1/0/1.100", "Vlan10"}, "ip": {"10.0.0.1", "2001:db8::1"}}
	bad := map[string][]string{"ap": {"-ap", "a b", "a|b", strings.Repeat("a", 33), ""}, "interface": {"1/0", "Gi1 /1", "Gi1/0;x", "G"}, "ip": {"10.0.0", "1.1.1.1 x", "fe80::1%eth0"}}
	for k, vs := range ok {
		for _, v := range vs {
			if _, err := ValidateValue(k, v); err != nil {
				t.Errorf("%s %q: %v", k, v, err)
			}
		}
	}
	for k, vs := range bad {
		for _, v := range vs {
			if _, err := ValidateValue(k, v); err == nil {
				t.Errorf("%s aceptó %q", k, v)
			}
		}
	}
}

func TestExpandRechecksDenied(t *testing.T) {
	// una plantilla que solo deja de ser lectura al sustituir
	p := Playbook{Platform: "ios-xe", Params: []Param{{"x", "ap"}}, Commands: []Command{{Text: "{x}"}}}
	if _, err := p.Expand(map[string]string{"x": "reload"}); err == nil {
		t.Error("CheckDenied no se repasó")
	}
}

// Un cuantificador de regex ({3}) en un filtro no es un dato: el playbook carga como antes.
func TestCuantificadorNoEsDato(t *testing.T) {
	if _, err := loadOne(t, "id: x\nplatform: ios-xe\nname: X\ncommands:\n  - cmd: show logging | include ^.{3}\n"); err != nil {
		t.Fatal(err)
	}
}

// En un 9800 corren los comandos marcados solo para ios-xe (dir bootflash: es su sistema de archivos principal).
func TestAppliesIOSXEEnWLC9800(t *testing.T) {
	c := Command{Text: "dir bootflash:", Platforms: []string{"ios-xe"}}
	if !c.Applies("wlc-9800") || c.Applies("ios") {
		t.Fatal("ios-xe debe aplicar en wlc-9800 y no en ios")
	}
}
