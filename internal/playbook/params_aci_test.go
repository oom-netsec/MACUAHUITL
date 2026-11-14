package playbook

import (
	"strings"
	"testing"
)

// Tipos de ACI: «vrf» es tenant:vrf (cada parte [A-Za-z0-9_.-], 1 a 64, un solo «:»); «vnid» es un entero 1-16777215.
func TestTiposVRFyVNID(t *testing.T) {
	buenos := map[string][]string{
		"vrf":  {"common:default", "t-1:v.2", "Tenant_A:VRF_1", strings.Repeat("a", 64) + ":" + strings.Repeat("b", 64)},
		"vnid": {"1", "2850817", "16777215"},
	}
	malos := map[string][]string{
		"vrf":  {"", "common", ":default", "common:", "a:b:c", strings.Repeat("a", 65) + ":b", "a:" + strings.Repeat("b", 65), "a b:c", "a:b?", "-x:y", "tftp:x/y", "a:b,c", "a:{b}", "tftp:x", "TFTP:x", "scp:a", "ftp:x", "http:y"},
		"vnid": {"", "0", "16777216", "01", "-1", "+5", "1e3", "0x10", "12a", " 12"},
	}
	for k, vs := range buenos {
		for _, v := range vs {
			if got, err := ValidateValue(k, v); err != nil || got != v {
				t.Errorf("%s %q: %q, %v", k, v, got, err)
			}
		}
	}
	for k, vs := range malos {
		for _, v := range vs {
			if _, err := ValidateValue(k, v); err == nil {
				t.Errorf("%s aceptó %q", k, v)
			}
		}
	}
	// El comando armado con los dos datos vuelve a pasar CheckDenied en nx-os (los leaf ACI pasan la línea a bash).
	p := Playbook{Platform: "nx-os", Params: []Param{{"vrf", "vrf"}, {"vnid", "vnid"}}, Commands: []Command{{Text: "show ip route vrf {vrf}"}, {Text: "show zoning-rule scope {vnid}"}}}
	out, err := p.Expand(map[string]string{"vrf": "common:default", "vnid": "2850817"})
	if err != nil || out[0].Text != "show ip route vrf common:default" || out[1].Text != "show zoning-rule scope 2850817" {
		t.Fatalf("%+v %v", out, err)
	}
}
