package compliance

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

type golden struct{ JSON, Text string }

func gold(v any, text string) golden {
	b, _ := json.Marshal(v)
	return golden{string(b), text}
}

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// regCases arma informes que recorren cada regla de endurecimiento y de la plantilla; solo usa lo que ya existía
// antes de la fase 30c. Sin secretos en las configuraciones (el enmascarado de la fase 30c amplía lo que se oculta).
func regCases(t *testing.T) (map[string]golden, map[string]any) {
	t.Helper()
	out, ptrs := map[string]golden{}, map[string]any{}
	run := func(name, cfg, tpl string) {
		r, err := Check(cfg, tpl)
		if err != nil {
			out[name] = gold(struct{ Err string }{err.Error()}, err.Error())
			return
		}
		out[name], ptrs[name] = gold(r, r.Text()), &r
	}
	debil, fuerte, plantilla := read(t, "debil.txt"), read(t, "endurecido.txt"), read(t, "plantilla.txt")
	run("debil", debil, "")
	run("endurecido", fuerte, "")
	run("endurecido-plantilla", fuerte, plantilla)
	run("minima", "hostname X\n", "")
	run("vty", "line vty 0 4\n transport input telnet\nline vty 5 15\nline vty 16 20\n transport input none\n", "")
	run("http", "ip http server\nip http secure-server\n", "")
	run("https-sin-auth", "ip http secure-server\n", "")
	run("https-con-auth", "ip http secure-server\nip http authentication local\n", "")
	run("ntp", "ntp server 10.0.0.1 key 1\nntp server 10.0.0.2\n", "")
	run("ntp-completo", "ntp authenticate\nntp authentication-key 1 md5 K\nntp trusted-key 1\nntp server 10.0.0.1 key 1\n", "")
	run("secretos", "enable secret 5 H\nusername ana secret 4 H\nline vty 0 4\n password 7 H\n", "")
	run("tiempo", "line con 0\n exec-timeout 0 0\nline vty 0 4\n exec-timeout 5 0\nline vty 5 15\n", "")
	run("tiempo-aviso", "line con 0\nline vty 0 4\n exec-timeout 5 0\n", "")
	run("copp", "control-plane\n service-policy input COPP\n", "")
	run("copp-sin", "control-plane\n", "")
	run("snmp", "snmp-server community public RO\nsnmp-server community uno RW\nsnmp-server community dos RO 10\n", "")
	run("snmp-acl", "snmp-server community dos RO 10\n", "")
	run("global-ok", "aaa new-model\nip ssh version 2\nservice password-encryption\nservice tcp-keepalives-in\nno ip source-route\nlogging host 10.0.0.9\nbanner motd ^C aviso ^C\n", "")
	// plantilla: opcional ausente, sección ausente, falta en varias, prohibida presente, errores
	run("tpl-opcional", "hostname SW1\n", "? interface Vlan\\d+\n + no ip proxy-arp\n")
	run("tpl-seccion", "hostname SW1\n", "line vty .*\n + transport input ssh\n")
	run("tpl-falta", "line vty 0 4\nline vty 5 15\n transport input ssh\n", "line vty .*\n + transport input ssh\n")
	run("tpl-prohibida", "hostname SW1\nip http server\n", "- ip http server\n+ hostname SW1\n")
	run("tpl-global", "hostname SW1\n", "+ service password-encryption\n")
	for i, tpl := range []string{"- foo\n bar\n", "? foo\n", "# nada\n", "+ (\n", " + a\n"} {
		run("tpl-error-"+string(rune('0'+i)), "hostname X\n", tpl)
	}
	run("config-vacia", "", "")
	run("config-espacios", "   \n", plantilla)
	return out, ptrs
}

func TestRegresionEs(t *testing.T) {
	got, _ := regCases(t)
	const file = "testdata/regresion_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]golden
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if got[n] != want[n] {
			t.Errorf("%s: el español cambió\n got: %+v\nwant: %+v", n, got[n], want[n])
		}
	}
	if len(want) != len(got) {
		t.Errorf("casos: %d vs %d", len(got), len(want))
	}
}
