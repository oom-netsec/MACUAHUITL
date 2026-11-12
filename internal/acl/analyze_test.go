package acl

import "testing"

func withPorts(r Rule, dst ...PortRange) Rule { r.DstPorts = dst; return r }

func TestCovers(t *testing.T) {
	ipAny := rule(Permit, "ip", "0.0.0.0/0", "0.0.0.0/0")
	tcpNet := withPorts(rule(Permit, "tcp", "10.0.0.0/24", "192.0.2.1/32"), PortRange{22, 22})
	if !ipAny.Covers(tcpNet) || tcpNet.Covers(ipAny) {
		t.Fatal("ip any any must cover everything and nothing covers it")
	}
	wide := withPorts(rule(Permit, "tcp", "10.0.0.0/8", "0.0.0.0/0"), PortRange{1, 1023})
	if !wide.Covers(tcpNet) {
		t.Fatal("wider net and port range should cover")
	}
	if wide.Covers(withPorts(rule(Permit, "tcp", "10.0.0.0/24", "0.0.0.0/0"), PortRange{1024, 1024})) {
		t.Fatal("port outside range covered")
	}
	if rule(Permit, "udp", "0.0.0.0/0", "0.0.0.0/0").Covers(tcpNet) {
		t.Fatal("udp covered tcp")
	}
	split := rule(Permit, "tcp", "0.0.0.0/0", "0.0.0.0/0")
	split.DstPorts = []PortRange{{0, 24}, {26, 65535}} // neq 25
	if !split.Covers(withPorts(rule(Permit, "tcp", "0.0.0.0/0", "0.0.0.0/0"), PortRange{80, 443})) {
		t.Fatal("range inside a multi-range set not covered")
	}
	if split.Covers(withPorts(rule(Permit, "tcp", "0.0.0.0/0", "0.0.0.0/0"), PortRange{20, 30})) {
		t.Fatal("range crossing the hole covered")
	}
}

func TestAnalyze(t *testing.T) {
	a := ACL{Name: "X", Rules: []Rule{
		withPorts(rule(Permit, "tcp", "10.0.0.0/24", "0.0.0.0/0"), PortRange{22, 22}),
		withPorts(rule(Deny, "tcp", "10.0.0.5/32", "0.0.0.0/0"), PortRange{22, 22}),   // sombreada por 0 (acción distinta)
		withPorts(rule(Permit, "tcp", "10.0.0.8/29", "0.0.0.0/0"), PortRange{22, 22}), // redundante con 0
		withPorts(rule(Permit, "tcp", "0.0.0.0/0", "0.0.0.0/0"), PortRange{100, 50}),  // imposible
		rule(Deny, "ip", "0.0.0.0/0", "0.0.0.0/0"),
	}}
	got := Analyze(a)
	want := map[int]string{1: "shadowed", 2: "redundant", 3: "impossible"}
	if len(got) != len(want) {
		t.Fatalf("findings = %+v", got)
	}
	for _, f := range got {
		if want[f.Index] != f.Kind || f.Detail == "" {
			t.Errorf("finding %+v", f)
		}
	}
}

func TestAnalyzeCleanACL(t *testing.T) {
	if got := Analyze(wantEdge()); len(got) != 0 {
		t.Fatalf("clean ACL produced %+v", got)
	}
}
