package compliance

import (
	"os"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
)

func load(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func byRule(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Rule] = f
	}
	return m
}

func TestHardeningOnHardenedConfigPasses(t *testing.T) {
	fs := Hardening(iosconf.Parse(load(t, "endurecido.txt")))
	if len(fs) != len(rules) {
		t.Fatalf("findings = %d, rules = %d", len(fs), len(rules))
	}
	for _, f := range fs {
		if f.Status != Pass {
			t.Errorf("%s: %s (%s)", f.Rule, f.Status, f.Detail)
		}
		if f.Reference == "" || f.Title == "" {
			t.Errorf("%s sin título o referencia", f.Rule)
		}
	}
}

func TestHardeningOnWeakConfig(t *testing.T) {
	m := byRule(Hardening(iosconf.Parse(load(t, "debil.txt"))))
	want := map[string]Status{
		"aaa-new-model": Fail, "ssh-v2": Fail, "vty-transport": Fail, "http-server": Fail, "ntp-auth": Fail,
		"logging-host": Fail, "password-encryption": Fail, "secret-types": Fail, "banner": Fail, "exec-timeout": Fail,
		"copp": Fail, "snmp-community": Fail, "source-route": Fail, "tcp-keepalives": Warn,
	}
	for id, st := range want {
		if m[id].Status != st {
			t.Errorf("%s = %s (%s), want %s", id, m[id].Status, m[id].Detail, st)
		}
	}
	if d := m["vty-transport"].Detail; !strings.Contains(d, "line vty 0 4") || !strings.Contains(d, "line vty 5 15") {
		t.Errorf("vty detail = %q", d)
	}
	if d := m["snmp-community"].Detail; !strings.Contains(d, "public") || !strings.Contains(d, "sin ACL") {
		t.Errorf("snmp detail = %q", d)
	}
	if len(m["secret-types"].Lines) < 2 {
		t.Errorf("secret lines = %v", m["secret-types"].Lines)
	}
}

func TestHardeningEdgeCases(t *testing.T) {
	cases := []struct {
		rule, cfg string
		want      Status
	}{
		{"vty-transport", "line vty 0 4\n transport input none\n", Pass},
		{"vty-transport", "line vty 0 4\n transport input all\n", Fail},
		{"vty-transport", "hostname x\n", Warn},
		{"http-server", "ip http secure-server\n", Fail},
		{"http-server", "ip http secure-server\nip http authentication aaa login-authentication X\n", Pass},
		{"secret-types", "enable secret 5 $1$x\n", Warn},
		{"secret-types", "enable secret 8 $8$x\n", Pass},
		{"secret-types", "enable secret 4 abc\n", Warn},
		{"secret-types", "username a privilege 15 secret 4 abc\n", Warn},
		{"secret-types", "line vty 0 4\n password 7 0822455D0A16\n", Warn},
		{"snmp-community", "snmp-server community S3cr3t RO 99\n", Warn},
		{"snmp-community", "snmp-server community S3cr3t view V RO ipv6 V6ACL\n", Fail},
		{"snmp-community", "snmp-server community private RW 10\n", Fail},
		{"exec-timeout", "line con 0\n exec-timeout 0\n", Fail},
		{"exec-timeout", "line con 0\n", Warn},
		{"ntp-auth", "ntp authenticate\nntp authentication-key 1 md5 x\nntp trusted-key 1\nntp server 192.0.2.1\n", Fail},
		{"logging-host", "logging 192.0.2.9\n", Pass},
		{"copp", "control-plane\n", Fail},
	}
	for _, c := range cases {
		m := byRule(Hardening(iosconf.Parse(c.cfg)))
		if m[c.rule].Status != c.want {
			t.Errorf("%s on %q = %s (%s), want %s", c.rule, c.cfg, m[c.rule].Status, m[c.rule].Detail, c.want)
		}
	}
}

func TestTemplate(t *testing.T) {
	tpl, err := ParseTemplate(load(t, "plantilla.txt"))
	if err != nil {
		t.Fatal(err)
	}
	good := byTitle(tpl.Check(iosconf.Parse(load(t, "endurecido.txt"))))
	for title, f := range good {
		if f.Status != Pass {
			t.Errorf("endurecido: %s = %s (%s)", title, f.Status, f.Detail)
		}
	}
	if len(good) != 9 {
		t.Fatalf("findings = %d: %v", len(good), good)
	}
	bad := byTitle(tpl.Check(iosconf.Parse(load(t, "debil.txt"))))
	for title, want := range map[string]Status{
		"+ service password-encryption":                       Fail,
		"+ hostname SW-ACC-\\d+":                              Pass,
		"- ip http server":                                    Fail,
		"- snmp-server community .*":                          Fail,
		"line vty .* > + transport input ssh":                 Fail,
		"line vty .* > - transport input .*telnet.*":          Fail,
		"? interface Vlan\\d+ > + no ip proxy-arp":            Fail,
		"control-plane > + service-policy input .*":           Fail,
		"line vty .* > + access-class ACL-VTY in( vrf-also)?": Fail,
	} {
		if bad[title].Status != want {
			t.Errorf("débil: %s = %s (%s), want %s", title, bad[title].Status, bad[title].Detail, want)
		}
	}
	if d := bad["- ip http server"].Detail; !strings.Contains(d, "línea") {
		t.Errorf("forbidden detail without line: %q", d)
	}
	if d := bad["control-plane > + service-policy input .*"].Detail; !strings.Contains(d, "no existe") {
		t.Errorf("missing section detail = %q", d)
	}
	// Sección opcional ausente: sus reglas no aplican.
	opt := byTitle(tpl.Check(iosconf.Parse("hostname SW-ACC-1\n")))
	if f := opt["? interface Vlan\\d+ > + no ip proxy-arp"]; f.Status != Pass || !strings.Contains(f.Detail, "no aplica") {
		t.Errorf("optional section = %+v", opt["? interface Vlan\\d+ > + no ip proxy-arp"])
	}
}

func TestTemplateBareLinesAreRequired(t *testing.T) {
	tpl, err := ParseTemplate("hostname X\nline con 0\n exec-timeout 5 0\n")
	if err != nil {
		t.Fatal(err)
	}
	m := byTitle(tpl.Check(iosconf.Parse("hostname X\nline con 0\n exec-timeout 0 0\n")))
	if m["hostname X"].Status != Pass || m["line con 0 > exec-timeout 5 0"].Status != Fail {
		t.Fatalf("%+v", m)
	}
}

func TestTemplateErrors(t *testing.T) {
	for _, bad := range []string{"+ (", "- ip http server\n x\n", "", "# solo comentario\n", "? opcional sin reglas\n"} {
		if _, err := ParseTemplate(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckReport(t *testing.T) {
	r, err := Check(load(t, "debil.txt"), load(t, "plantilla.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Fail == 0 || r.Pass == 0 || len(r.Template) == 0 || len(r.Hardening) != len(rules) || !strings.Contains(r.Note, "sin validar en laboratorio") {
		t.Fatalf("report = %+v", r)
	}
	txt := r.Text()
	if !strings.Contains(txt, "FALLA") || !strings.Contains(txt, "aaa-new-model") {
		t.Fatalf("text:\n%s", txt)
	}
	if _, err := Check("  \n", ""); err == nil {
		t.Fatal("empty config accepted")
	}
}

func byTitle(fs []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range fs {
		m[f.Title] = f
	}
	return m
}

func TestSecretTypesNoImprimeSecreto(t *testing.T) {
	cfg := "enable password 0 hunter2\nusername a password 7 0822455D0A16\nline vty 0 4\n password 7 1511021F0725\n"
	f := byRule(Hardening(iosconf.Parse(cfg)))["secret-types"]
	for _, s := range []string{"hunter2", "0822455D0A16", "1511021F0725"} {
		if strings.Contains(f.Detail, s) {
			t.Errorf("el detalle expone %q: %s", s, f.Detail)
		}
	}
}
