package acl

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func wantEdge() ACL {
	p := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	return ACL{Name: "EDGE-IN", Rules: []Rule{
		{Action: Permit, Protocol: "tcp", Src: p("10.10.0.0/24"), Dst: p("192.0.2.1/32"), DstPorts: []PortRange{{22, 22}}, Log: true, Remark: "Gestion desde la red de NOC"},
		{Action: Permit, Protocol: "udp", Src: Any, SrcPorts: []PortRange{{123, 123}}, Dst: p("192.0.2.1/32"), DstPorts: []PortRange{{123, 123}}},
		{Action: Permit, Protocol: "tcp", Src: p("10.20.0.0/16"), Dst: Any, DstPorts: []PortRange{{1024, 65535}}},
		{Action: Deny, Protocol: "ip", Src: Any, Dst: Any, Log: true},
	}}
}

func TestParseAllVendors(t *testing.T) {
	for vendor, file := range map[string]string{"ios-xe": "iosxe.txt", "nx-os": "nxos.txt", "asa": "asa.txt"} {
		b, err := os.ReadFile(filepath.Join("testdata", file))
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(vendor, string(b))
		if err != nil {
			t.Fatalf("%s: %v", vendor, err)
		}
		if !reflect.DeepEqual(got, wantEdge()) {
			t.Errorf("%s:\n got %+v\nwant %+v", vendor, got, wantEdge())
		}
	}
}

func TestParseNumberedIOS(t *testing.T) {
	got, err := Parse("ios-xe", "access-list 101 permit tcp any host 10.0.0.1 eq www\naccess-list 101 deny ip any any\n")
	if err != nil || got.Name != "101" || len(got.Rules) != 2 || got.Rules[0].DstPorts[0].Lo != 80 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestParseErrorsNameLine(t *testing.T) {
	cases := map[string]string{
		"wildcard no contigua":  "ip access-list extended X\n permit ip 10.0.0.0 0.0.255.0 any\n",
		"protocolo desconocido": "ip access-list extended X\n permit nada any any\n",
		"puertos con ip":        "ip access-list extended X\n permit ip any any eq 22\n",
		"sin destino":           "ip access-list extended X\n permit tcp any\n",
		"sin encabezado":        " permit ip any any\n",
		"fabricante":            "ip access-list extended X\n permit ip any any\n",
	}
	for name, text := range cases {
		vendor := "ios-xe"
		if name == "fabricante" {
			vendor = "junos"
		}
		_, err := Parse(vendor, text)
		var le *LineError
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if name != "fabricante" && (!errors.As(err, &le) || le.Line != 2 && name != "sin encabezado") {
			t.Errorf("%s: err = %v (want LineError with line)", name, err)
		}
	}
}

func TestASAMaskIsNetmaskNotWildcard(t *testing.T) {
	got, err := Parse("asa", "access-list X extended permit ip 10.1.0.0 255.255.0.0 any\n")
	if err != nil || got.Rules[0].Src.String() != "10.1.0.0/16" {
		t.Fatalf("%+v %v", got, err)
	}
	ios, err := Parse("ios-xe", "ip access-list extended X\n permit ip 10.1.0.0 0.0.255.255 any\n")
	if err != nil || ios.Rules[0].Src.String() != "10.1.0.0/16" {
		t.Fatalf("%+v %v", ios, err)
	}
	if _, err := Parse("ios-xe", "ip access-list extended X\n permit ip 10.1.0.0 255.255.0.0 any\n"); err == nil {
		t.Fatal("netmask accepted as IOS wildcard")
	}
}

func TestParseIgnoresNoise(t *testing.T) {
	got, err := Parse("ios-xe", "!\nBuilding configuration...\n\nip access-list extended X\n permit ip any any\n!\nend\n")
	if err != nil || len(got.Rules) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}
