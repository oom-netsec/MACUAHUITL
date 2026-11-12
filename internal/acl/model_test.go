package acl

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		op   string
		args []string
		want []PortRange
	}{
		{"eq", []string{"22"}, []PortRange{{22, 22}}},
		{"eq", []string{"ssh"}, []PortRange{{22, 22}}},
		{"eq", []string{"www"}, []PortRange{{80, 80}}},
		{"eq", []string{"domain"}, []PortRange{{53, 53}}},
		{"range", []string{"1024", "65535"}, []PortRange{{1024, 65535}}},
		{"gt", []string{"1023"}, []PortRange{{1024, 65535}}},
		{"lt", []string{"1024"}, []PortRange{{0, 1023}}},
		{"neq", []string{"25"}, []PortRange{{0, 24}, {26, 65535}}},
		{"neq", []string{"0"}, []PortRange{{1, 65535}}},
	}
	for _, c := range cases {
		got, err := ParsePorts(c.op, c.args...)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("ParsePorts(%s %v) = %v, %v; want %v", c.op, c.args, got, err, c.want)
		}
	}
	for _, bad := range [][]string{{"gt", "65535"}, {"lt", "0"}, {"range", "100", "50"}, {"eq", "nada"}, {"eq", "70000"}, {"range", "1"}, {"between", "1", "2"}} {
		if _, err := ParsePorts(bad[0], bad[1:]...); err == nil {
			t.Errorf("ParsePorts(%v) accepted", bad)
		}
	}
}

func TestProtocolNumber(t *testing.T) {
	for name, want := range map[string]int{"ip": 0, "icmp": 1, "tcp": 6, "udp": 17, "47": 47, "esp": 50, "gre": 47} {
		if got, ok := ProtocolNumber(name); !ok || got != want {
			t.Errorf("ProtocolNumber(%s) = %d, %v", name, got, ok)
		}
	}
	if _, ok := ProtocolNumber("nada"); ok {
		t.Error("unknown protocol accepted")
	}
}

func rule(act Action, proto, src, dst string) Rule {
	return Rule{Action: act, Protocol: proto, Src: netip.MustParsePrefix(src), Dst: netip.MustParsePrefix(dst)}
}

func TestValidate(t *testing.T) {
	ok := rule(Permit, "tcp", "10.0.0.0/24", "0.0.0.0/0")
	ok.DstPorts = []PortRange{{22, 22}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := rule(Permit, "ip", "10.0.0.0/24", "0.0.0.0/0")
	bad.DstPorts = []PortRange{{22, 22}}
	if err := bad.Validate(); err == nil {
		t.Error("ports with protocol ip accepted")
	}
	if err := rule(Permit, "nada", "10.0.0.0/24", "0.0.0.0/0").Validate(); err == nil {
		t.Error("unknown protocol accepted")
	}
	if err := (Rule{Action: Permit, Protocol: "ip"}).Validate(); err == nil {
		t.Error("zero prefixes accepted")
	}
}
