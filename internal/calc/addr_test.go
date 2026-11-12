package calc

import (
	"strings"
	"testing"
)

func TestSubnetIPv4(t *testing.T) {
	cases := []struct {
		in                                string
		net, bcast, first, last, mask, wc string
		total, usable, kind, class        string
	}{
		{"192.168.10.77/26", "192.168.10.64", "192.168.10.127", "192.168.10.65", "192.168.10.126", "255.255.255.192", "0.0.0.63", "64", "62", "privada (RFC 1918)", "C"},
		{"10.1.2.3 255.255.0.0", "10.1.0.0", "10.1.255.255", "10.1.0.1", "10.1.255.254", "255.255.0.0", "0.0.255.255", "65536", "65534", "privada (RFC 1918)", "A"},
		{"0.0.0.0/0", "0.0.0.0", "255.255.255.255", "0.0.0.1", "255.255.255.254", "0.0.0.0", "255.255.255.255", "4294967296", "4294967294", "cualquiera (ruta por defecto)", "A"},
		// /31 punto a punto (RFC 3021): sin red ni broadcast, dos hosts.
		{"203.0.113.8/31", "203.0.113.8", "", "203.0.113.8", "203.0.113.9", "255.255.255.254", "0.0.0.1", "2", "2", "documentación (RFC 5737)", "C"},
		{"8.8.8.8/32", "8.8.8.8", "", "8.8.8.8", "8.8.8.8", "255.255.255.255", "0.0.0.0", "1", "1", "pública", "A"},
		{"100.64.1.1/10", "100.64.0.0", "100.127.255.255", "100.64.0.1", "100.127.255.254", "255.192.0.0", "0.63.255.255", "4194304", "4194302", "CGNAT (RFC 6598)", "A"},
		{"224.0.0.5/32", "224.0.0.5", "", "224.0.0.5", "224.0.0.5", "255.255.255.255", "0.0.0.0", "1", "1", "multicast local (RFC 5771)", "D"},
		{"169.254.9.9/16", "169.254.0.0", "169.254.255.255", "169.254.0.1", "169.254.255.254", "255.255.0.0", "0.0.255.255", "65536", "65534", "enlace local (RFC 3927)", "B"},
	}
	for _, c := range cases {
		s, err := Subnet(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		got := []string{s.Network, s.Broadcast, s.FirstUsable, s.LastUsable, s.Mask, s.Wildcard, s.Total, s.Usable, s.Kind, s.Class}
		want := []string{c.net, c.bcast, c.first, c.last, c.mask, c.wc, c.total, c.usable, c.kind, c.class}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s:\n got %v\nwant %v", c.in, got, want)
		}
	}
}

func TestSubnetIPv6(t *testing.T) {
	cases := []struct{ in, net, first, last, total, usable, kind string }{
		{"2001:db8:a::1/64", "2001:db8:a::/64", "2001:db8:a::", "2001:db8:a:0:ffff:ffff:ffff:ffff", "18446744073709551616", "18446744073709551616", "documentación (RFC 3849)"},
		{"2001:db8::1/127", "2001:db8::/127", "2001:db8::", "2001:db8::1", "2", "2", "documentación (RFC 3849)"},
		{"fe80::1/128", "fe80::1/128", "fe80::1", "fe80::1", "1", "1", "enlace local (RFC 4291)"},
		{"::/0", "::/0", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "340282366920938463463374607431768211456", "340282366920938463463374607431768211456", "cualquiera (ruta por defecto)"},
	}
	for _, c := range cases {
		s, err := Subnet(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		got := []string{s.Prefix, s.FirstUsable, s.LastUsable, s.Total, s.Usable, s.Kind}
		want := []string{c.net, c.first, c.last, c.total, c.usable, c.kind}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("%s:\n got %v\nwant %v", c.in, got, want)
		}
		if s.Broadcast != "" || s.Mask != "" {
			t.Errorf("%s: IPv6 sin broadcast ni máscara: %+v", c.in, s)
		}
	}
}

// El tipo es del prefijo completo: solo se etiqueta si un bloque especial lo contiene entero.
func TestSubnetKindCoversWholePrefix(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.0/7": "mixta (cubre bloques de distinto tipo)", "224.0.0.0/3": "mixta (cubre bloques de distinto tipo)",
		"172.16.4.0/22": "privada (RFC 1918)", "224.0.0.0/20": "multicast (RFC 5771)", "8.0.0.0/7": "pública",
		"fc00::/6": "mixta (cubre bloques de distinto tipo)", "2001:db8:1::/48": "documentación (RFC 3849)",
	} {
		s, err := Subnet(in)
		if err != nil || s.Kind != want {
			t.Errorf("%s: %q %v, quiero %q", in, s.Kind, err, want)
		}
	}
}

func TestSubnetRejects(t *testing.T) {
	for _, in := range []string{"", "10.0.0.0/33", "10.0.0.0 255.0.255.0", "300.1.1.1/8", "2001:db8::/129", "x/24", "10.0.0.0"} {
		if _, err := Subnet(in); err == nil {
			t.Errorf("%q aceptado", in)
		}
	}
}

func TestVLSM(t *testing.T) {
	v, err := VLSM("192.168.1.0/24", []Need{{"A", 50}, {"B", 100}, {"C", 2}, {"D", 20}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, a := range v.Allocations {
		got = append(got, a.Name+"="+a.Prefix)
	}
	want := "B=192.168.1.0/25 A=192.168.1.128/26 D=192.168.1.192/27 C=192.168.1.224/30"
	if strings.Join(got, " ") != want {
		t.Fatalf("got %v", got)
	}
	if len(v.Unplaced) != 0 || strings.Join(v.Free, " ") != "192.168.1.228/30 192.168.1.232/29 192.168.1.240/28" {
		t.Fatalf("unplaced %v free %v", v.Unplaced, v.Free)
	}
	// Lo que no cabe se reporta y lo más chico aún se acomoda.
	v, err = VLSM("10.0.0.0/28", []Need{{"grande", 20}, {"p2p", 2}, {"media", 10}, {"otra", 6}})
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Allocations) != 1 || v.Allocations[0].Prefix != "10.0.0.0/28" || v.Allocations[0].Name != "media" ||
		strings.Join(v.Unplaced, ",") != "grande (20 hosts),otra (6 hosts),p2p (2 hosts)" {
		t.Fatalf("%+v", v)
	}
	// Bloque que termina en 255.255.255.255: el siguiente no debe dar la vuelta a 0.0.0.0.
	v, err = VLSM("255.255.255.252/30", []Need{{"a", 2}, {"b", 2}})
	if err != nil || len(v.Allocations) != 1 || len(v.Unplaced) != 1 {
		t.Fatalf("%+v %v", v, err)
	}
	v, err = VLSM("2001:db8::/62", []Need{{"x", 1 << 40}, {"y", 300}})
	if err != nil || v.Allocations[0].Prefix != "2001:db8::/88" || v.Allocations[1].Prefix != "2001:db8::100:0:0/119" {
		t.Fatalf("%+v %v", v, err)
	}
	// Una necesidad absurda en IPv4 no debe desbordar el cálculo del bloque.
	if v, err = VLSM("0.0.0.0/0", []Need{{"x", 1<<64 - 1}}); err != nil || len(v.Unplaced) != 1 {
		t.Fatalf("%+v %v", v, err)
	}
	if _, err := VLSM("10.0.0.0/24", []Need{{"x", 0}}); err == nil {
		t.Fatal("0 hosts aceptado")
	}
}

func TestSummarize(t *testing.T) {
	s, err := Summarize([]string{"10.1.0.0/24", "10.1.1.0/24", "10.1.2.0/24", "10.1.3.0/24"})
	if err != nil || s.Single != "10.1.0.0/22" || strings.Join(s.Exact, " ") != "10.1.0.0/22" || s.Extra != "0" {
		t.Fatalf("%+v %v", s, err)
	}
	s, err = Summarize([]string{"172.16.5.0/24", "172.16.1.0/24", "172.16.2.128/25", "172.16.1.64/26"})
	if err != nil || s.Single != "172.16.0.0/21" || strings.Join(s.Exact, " ") != "172.16.1.0/24 172.16.2.128/25 172.16.5.0/24" || s.Extra != "1408" {
		t.Fatalf("%+v %v", s, err)
	}
	s, err = Summarize([]string{"0.0.0.0/1", "128.0.0.0/1"})
	if err != nil || s.Single != "0.0.0.0/0" || strings.Join(s.Exact, " ") != "0.0.0.0/0" {
		t.Fatalf("%+v %v", s, err)
	}
	s, err = Summarize([]string{"2001:db8:0:1::/64", "2001:db8:0:2::/64", "2001:db8:0:3::/64"})
	if err != nil || s.Single != "2001:db8::/62" || strings.Join(s.Exact, " ") != "2001:db8:0:1::/64 2001:db8:0:2::/63" {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := Summarize([]string{"10.0.0.0/8", "2001:db8::/32"}); err == nil {
		t.Fatal("familias mezcladas aceptadas")
	}
}

func TestWildcardConvert(t *testing.T) {
	for in, want := range map[string]string{
		"/24": "/24 255.255.255.0 0.0.0.255", "24": "/24 255.255.255.0 0.0.0.255",
		"255.255.255.252": "/30 255.255.255.252 0.0.0.3", "0.0.15.255": "/20 255.255.240.0 0.0.15.255",
		"0": "/0 0.0.0.0 255.255.255.255", "32": "/32 255.255.255.255 0.0.0.0",
	} {
		w, err := Wildcard("", in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got := "/" + w.PrefixLen + " " + w.Mask + " " + w.Wildcard; got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
	if _, err := Wildcard("", "255.0.255.0"); err == nil {
		t.Error("máscara no contigua aceptada sin dirección")
	}
}

func TestWildcardACLCoverage(t *testing.T) {
	// Clásico: hosts impares de 10.1.1.0/24.
	w, err := Wildcard("10.1.1.1", "0.0.0.254")
	if err != nil {
		t.Fatal(err)
	}
	if w.Matches != "128" || w.Contiguous || w.First != "10.1.1.1" || w.Last != "10.1.1.255" || len(w.Prefixes) != 16 || w.Prefixes[1] != "10.1.1.3/32" || w.PrefixCount != "128" {
		t.Fatalf("%+v", w)
	}
	// Terceros octetos pares de 10.0.0.0/16, cada uno un /24.
	w, err = Wildcard("10.0.0.0", "0.0.254.255")
	if err != nil {
		t.Fatal(err)
	}
	if w.Matches != "32768" || w.PrefixCount != "128" || w.Prefixes[0] != "10.0.0.0/24" || w.Prefixes[1] != "10.0.2.0/24" || w.Octets[2].Values != "pares de 0 a 254" {
		t.Fatalf("%+v", w)
	}
	// Bits de host encendidos en la dirección: IOS los descarta.
	w, err = Wildcard("192.168.1.77", "0.0.0.255")
	if err != nil || !w.Contiguous || w.Base != "192.168.1.0" || w.Prefixes[0] != "192.168.1.0/24" {
		t.Fatalf("%+v %v", w, err)
	}
	if _, err := Wildcard("2001:db8::", "::ff"); err == nil {
		t.Fatal("wildcard IPv6 aceptada")
	}
}

func TestIPv6Info(t *testing.T) {
	r, err := IPv6("2001:0DB8:0000:0000:0000:ff00:0042:8329", "")
	if err != nil || r.Compressed != "2001:db8::ff00:42:8329" || r.Expanded != "2001:0db8:0000:0000:0000:ff00:0042:8329" || r.Kind != "documentación (RFC 3849)" ||
		r.SolicitedNode != "ff02::1:ff42:8329" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = IPv6("ff02::1:ff00:1", "")
	if err != nil || r.Kind != "multicast nodo solicitado (RFC 4291)" || r.SolicitedNode != "" {
		t.Fatalf("%+v %v", r, err)
	}
	// EUI-64: se invierte el bit U/L y se inserta fffe.
	r, err = IPv6("2001:db8:1:2::/64", "0050.56AB.cdef")
	if err != nil || r.EUI64 != "2001:db8:1:2:250:56ff:feab:cdef" || r.InterfaceID != "0250:56ff:feab:cdef" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = IPv6("", "02-00-00-00-00-01")
	if err != nil || r.EUI64 != "fe80::ff:fe00:1" {
		t.Fatalf("%+v %v", r, err)
	}
	// Una dirección EUI-64 revela la MAC.
	r, err = IPv6("fe80::250:56ff:feab:cdef", "")
	if err != nil || r.MAC != "00:50:56:ab:cd:ef" {
		t.Fatalf("%+v %v", r, err)
	}
	for _, bad := range [][2]string{{"10.0.0.1", ""}, {"", "00:11:22"}, {"2001:db8::/48", "00:11:22:33:44:55"}, {"", ""}} {
		if _, err := IPv6(bad[0], bad[1]); err == nil {
			t.Errorf("%v aceptado", bad)
		}
	}
}
