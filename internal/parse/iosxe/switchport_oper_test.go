package iosxe

import "testing"

func TestParseSwitchportOperMode(t *testing.T) {
	out := fx(t, "sw3560cx_show-interfaces-switchport")
	if m, ok := ParseSwitchportMode(out); !ok || m != "dynamic auto" {
		t.Fatalf("admin %q %v", m, ok)
	}
	if m, ok := ParseSwitchportOperMode(out); !ok || m != "down" {
		t.Fatalf("oper %q %v", m, ok)
	}
	if m, _ := ParseSwitchportOperMode("Administrative Mode: dynamic desirable\nOperational Mode: trunk\n"); m != "trunk" {
		t.Fatalf("%q", m)
	}
	if _, ok := ParseSwitchportOperMode("Name: Gi0/0\nSwitchport: Disabled\n"); ok {
		t.Fatal("sin línea Operational Mode")
	}
}
