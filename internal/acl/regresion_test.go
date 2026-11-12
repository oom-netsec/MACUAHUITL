package acl

import (
	"encoding/json"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

// regErrs son los errores que produjo la última corrida de regCases (para comprobar qué códigos recorre).
var regErrs []error

// regCases fija el texto en español de cada error de importación, validación y generación y de cada hallazgo;
// solo usa lo que ya existía antes de la fase 30c.
func regCases(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	msg := func(name string, err error) {
		if err == nil {
			out[name] = "<sin error>"
			return
		}
		out[name] = err.Error()
		regErrs = append(regErrs, err)
	}
	regErrs = nil
	for _, v := range []string{"junos", "ios-xe", "nx-os", "asa"} {
		for i, txt := range []string{
			"", "basura\n", "access-list 10 permit any\n", "ip access-list standard X\n", "permit ip any any\n",
			"ip access-list extended A\npermit ip any any\nip access-list extended B\n",
			"ip access-list extended A\nallow ip any any\n", "ip access-list extended A\npermit\n", "ip access-list extended A\npermit foo any any\n",
			"ip access-list extended A\npermit ip any any fragments\n", "ip access-list extended A\npermit ip\n",
			"ip access-list extended A\npermit ip 10.0.0.0 0.0.255.0 any\n", "ip access-list extended A\npermit ip any 10.0.0.0/33\n",
			"ip access-list extended A\npermit tcp any eq any\n", "ip access-list extended A\npermit tcp any eq 99999 any\n",
			"ip access-list extended A\npermit tcp any range 9 5 any\n", "ip access-list extended A\npermit tcp any gt 65535 any\n",
			"ip access-list extended A\npermit tcp any lt 0 any\n", "ip access-list extended A\npermit tcp any neq 1 2 any\n",
			"ip access-list extended A\npermit tcp any any established log fragments\n", "ip access-list extended A\npermit ip host any\n",
			"ip access-list extended A\npermit ip 10.0.0.0 any\n", "ip access-list extended A\npermit ip host\n", "ip access-list extended A\npermit ip 10.0.0.0\n", "ip access-list A\npermit ip 10.0.0.0/zz any\n", "access-list X extended permit ip 10.0.0.0\n", "access-list X extended permit ip 10.0.0.0 foo any\n", "access-list X extended permit ip host\n", "ip access-list extended A\npermit ip 10.0.0.0 foo any\n", "ip access-list extended A\npermit ip 10.0.0.0 255.0.255.0 any\n",
			"ip access-list extended A\npermit ip 300.0.0.1 0.0.0.0 any\n", "ip access-list extended A\npermit ip 10.0.0.1/8 any\n",
			"fragments deny-all\n", "ip access-list A\nstatistics per-entry\nfragments permit-all\n",
			"access-list X extended permit ip any any\naccess-list Y extended permit ip any any\n", "access-list X extended\n",
			"access-list X extended permit ip 10.0.0.0 0.0.0.255 any\n", "access-list X extended permit tcp any any eq\n",
		} {
			_, err := Parse(v, txt)
			msg("parse-"+v+"-"+string(rune('a'+i%26))+string(rune('a'+i/26)), err)
		}
	}
	rules := func(mod func(*Rule)) ACL {
		r := Rule{Action: Permit, Protocol: "ip", Src: mustPrefix("10.0.0.0/8"), Dst: mustPrefix("0.0.0.0/0")}
		mod(&r)
		return ACL{Name: "T", Rules: []Rule{r}}
	}
	for name, mod := range map[string]func(*Rule){
		"proto": func(r *Rule) { r.Protocol = "zz" }, "vacio": func(r *Rule) { r.Src = netip.Prefix{} },
		"ipv6": func(r *Rule) { r.Src = mustPrefix("2001:db8::/32") }, "host": func(r *Rule) { r.Src = mustPrefix("10.0.0.1/8") },
		"remark": func(r *Rule) { r.Remark = "a\nb" }, "puertos": func(r *Rule) { r.DstPorts = []PortRange{{80, 80}} },
		"established": func(r *Rule) { r.Established = true }, "established-tcp": func(r *Rule) { r.Protocol = "tcp"; r.Established = true }, "rango": func(r *Rule) { r.Protocol = "tcp"; r.DstPorts = []PortRange{{90, 80}} },
	} {
		msg("validate-"+name, rules(mod).Rules[0].Validate())
		for _, v := range []string{"ios-xe", "nx-os", "asa", "junos"} {
			_, err := Generate(v, rules(mod))
			msg("generate-"+v+"-"+name, err)
		}
	}
	for i, c := range [][]string{{"zzz", "9"}, {"range", "9"}, {"eq"}, {"range", "9", "5"}, {"gt", "65535"}, {"lt", "0"}, {"eq", "99999"}} {
		_, err := ParsePorts(c[0], c[1:]...)
		msg("ports-"+string(rune('a'+i)), err)
	}
	_, err := Generate("ios-xe", ACL{Name: "a b"})
	msg("generate-nombre", err)
	// hallazgos
	a := ACL{Name: "T", Rules: []Rule{
		{Action: Permit, Protocol: "ip", Src: mustPrefix("10.0.0.0/8"), Dst: mustPrefix("0.0.0.0/0")},
		{Action: Deny, Protocol: "tcp", Src: mustPrefix("10.1.0.0/16"), Dst: mustPrefix("0.0.0.0/0")},
		{Action: Permit, Protocol: "tcp", Src: mustPrefix("10.1.0.0/16"), Dst: mustPrefix("0.0.0.0/0")},
		{Action: Permit, Protocol: "icmp", Src: mustPrefix("10.0.0.0/8"), Dst: mustPrefix("0.0.0.0/0"), DstPorts: []PortRange{{80, 80}}},
	}}
	var fs []string
	for _, f := range Analyze(a) {
		b, _ := json.Marshal(struct {
			Index        int
			Kind, Detail string
		}{f.Index, f.Kind, f.Detail})
		fs = append(fs, string(b))
	}
	out["analyze"] = strings.Join(fs, "\n")
	return out
}

func TestRegresionEs(t *testing.T) {
	got := regCases(t)
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
	var want map[string]string
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
			t.Errorf("%s: el español cambió\n got: %q\nwant: %q", n, got[n], want[n])
		}
	}
	if len(want) != len(got) {
		t.Errorf("casos: %d vs %d", len(got), len(want))
	}
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
