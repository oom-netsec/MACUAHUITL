package acl

import (
	"net/netip"
	"strings"
	"testing"
)

func TestFullRangeIsAnyPort(t *testing.T) {
	a := ACL{Name: "X", Rules: []Rule{{Action: Permit, Protocol: "tcp", Src: Any, Dst: Any, DstPorts: []PortRange{{0, 65535}}}}}
	for _, v := range Vendors {
		s, err := Generate(v, a)
		if err != nil || strings.Contains(s, "lt 0") || strings.Contains(s, "range 0 65535") {
			t.Fatalf("%s: %q %v", v, s, err)
		}
	}
	if _, err := Parse("ios-xe", "ip access-list extended X\n permit tcp any any range 0 65535\n"); err != nil {
		t.Fatal(err)
	}
}

func TestNeqWithSeveralPortsRejected(t *testing.T) {
	if _, err := Parse("ios-xe", "ip access-list extended X\n deny tcp any any neq 25 80\n"); err == nil || !strings.Contains(err.Error(), "línea 2") {
		t.Fatalf("neq with two ports must fail with a line: %v", err)
	}
}

func TestMultiPortEqPerVendor(t *testing.T) {
	a, err := Parse("ios-xe", "ip access-list extended X\n permit tcp any any eq 80 443\n deny ip any any\n")
	if err != nil || len(a.Rules) != 2 || len(a.Rules[0].DstPorts) != 2 {
		t.Fatalf("%+v %v", a, err)
	}
	for _, v := range []string{"nx-os", "asa"} {
		s, err := Generate(v, a)
		if err != nil || strings.Contains(s, "eq 80 443") || strings.Count(s, "eq 80")+strings.Count(s, "eq 443") != 2 {
			t.Fatalf("%s must emit one line per port:\n%s %v", v, s, err)
		}
		back, err := Parse(v, s)
		if err != nil || len(back.Rules) != 3 {
			t.Fatalf("%s round trip: %+v %v", v, back, err)
		}
	}
	ios, _ := Generate("ios-xe", a)
	if !strings.Contains(ios, "eq 80 443") {
		t.Fatalf("ios should keep eq 80 443:\n%s", ios)
	}
	// Más de 10 puertos sueltos en IOS: una línea por puerto, no una lista que IOS rechaza.
	many := Rule{Action: Permit, Protocol: "tcp", Src: Any, Dst: Any}
	for p := uint16(1000); p < 1024; p += 2 {
		many.DstPorts = append(many.DstPorts, PortRange{p, p})
	}
	s, err := Generate("ios-xe", ACL{Name: "Y", Rules: []Rule{many}})
	if err != nil || strings.Count(s, "permit tcp") < 2 {
		t.Fatalf("12 ports in one eq:\n%s %v", s, err)
	}
}

func TestValidateRejectsIPv6AndUnmasked(t *testing.T) {
	r := Rule{Action: Permit, Protocol: "ip", Src: netip.MustParsePrefix("2001:db8::/64"), Dst: Any}
	if err := r.Validate(); err == nil {
		t.Fatal("ipv6 accepted (would panic in the generator)")
	}
	r = Rule{Action: Permit, Protocol: "ip", Src: netip.MustParsePrefix("10.0.0.5/24"), Dst: Any}
	if err := r.Validate(); err == nil {
		t.Fatal("unmasked prefix accepted")
	}
	r = Rule{Action: Permit, Protocol: "ip", Src: Any, Dst: Any, Remark: "a\nb"}
	if err := r.Validate(); err == nil {
		t.Fatal("remark with newline accepted (would inject a line)")
	}
	if _, err := Generate("ios-xe", ACL{Name: "X", Rules: []Rule{{Action: Permit, Protocol: "ip", Src: netip.MustParsePrefix("2001:db8::/64"), Dst: Any}}}); err == nil {
		t.Fatal("generate with ipv6 did not fail cleanly")
	}
}

func TestTwoACLsInOnePasteRejected(t *testing.T) {
	_, err := Parse("ios-xe", "ip access-list extended A\n permit ip any any\nip access-list extended B\n deny ip any any\n")
	if err == nil || !strings.Contains(err.Error(), "línea 3") {
		t.Fatalf("second ACL silently merged: %v", err)
	}
	_, err = Parse("asa", "access-list A extended permit ip any any\naccess-list B extended deny ip any any\n")
	if err == nil || !strings.Contains(err.Error(), "línea 2") {
		t.Fatalf("asa second ACL silently merged: %v", err)
	}
}

func TestNxosFragmentsRejected(t *testing.T) {
	_, err := Parse("nx-os", "ip access-list X\n  fragments permit-all\n  10 permit ip any any\n")
	if err == nil || !strings.Contains(err.Error(), "línea 2") {
		t.Fatalf("fragments dropped silently: %v", err)
	}
	if _, err := Parse("nx-os", "ip access-list X\n  statistics per-entry\n  10 permit ip any any\n"); err != nil {
		t.Fatal(err)
	}
}

func TestRemarksKept(t *testing.T) {
	a, err := Parse("ios-xe", "ip access-list extended X\n remark uno\n remark dos\n permit ip any any\n remark colgado\n")
	if err != nil || a.Rules[0].Remark != "uno / dos" {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestProtocolNumbersNormalized(t *testing.T) {
	a, err := Parse("ios-xe", "ip access-list extended X\n permit 6 any any eq 22\n permit tcp any any eq 22\n")
	if err != nil || a.Rules[0].Protocol != "tcp" {
		t.Fatalf("%+v %v", a, err)
	}
	if f := Analyze(a); len(f) != 1 || f[0].Kind != "redundant" {
		t.Fatalf("findings = %+v", f)
	}
}
