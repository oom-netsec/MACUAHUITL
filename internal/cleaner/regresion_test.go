package cleaner

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

type golden struct{ JSON, Text, Output string }

func gold(r Result) golden {
	out := r.Output
	r.Output = ""
	b, _ := json.Marshal(r)
	return golden{string(b), r.Text(), out}
}

// regCases limpia configuraciones con cada tipo de cambio y de huérfana; solo usa lo que ya existía antes de la fase 30c.
func regCases(t *testing.T) (map[string]golden, map[string]*Result) {
	t.Helper()
	out, ptrs := map[string]golden{}, map[string]*Result{}
	sucia, err := os.ReadFile("testdata/sucia.txt")
	if err != nil {
		t.Fatal(err)
	}
	run := func(name, text string, o Options) {
		r := Clean(text, o)
		out[name], ptrs[name] = gold(r), &r
	}
	run("sucia", string(sucia), Options{})
	run("sucia-orden", string(sucia), Options{Sort: true})
	run("vacia", "", Options{})
	run("limpia", "hostname A\n!\ninterface Gi1\n", Options{})
	run("crlf", "hostname A  \r\n\r\n!\r\n!\r\ninterface Gi1\r\n", Options{Sort: true})
	run("interfaces-desordenadas", "interface Gi1/0/10\n shutdown\ninterface Gi1/0/2\n shutdown\ninterface Gi1/0/1\n shutdown\nvlan 20\nvlan 10\nip route 10.2.0.0 255.255.0.0 10.0.0.1\nip route 10.1.0.0 255.255.0.0 10.0.0.1\nusername b secret 5 x\nusername a secret 5 x\n", Options{Sort: true})
	run("huerfanas", "class-map match-all SOLA\n match dscp ef\npolicy-map P\n class NOEXISTE\ninterface Gi1\n ip access-group SIN-ACL in\n service-policy input SIN-POLICY\nline vty 0 4\n access-class SIN-ACL2 in\nroute-map RM permit 10\n match ip address SIN-ACL3\nrouter ospf 1\n redistribute static route-map SIN-RM\n", Options{})
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
