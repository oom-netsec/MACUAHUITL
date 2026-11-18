package diag

import (
	"net/netip"
	"reflect"
	"testing"
)

func ips(s ...string) []netip.Addr {
	var out []netip.Addr
	for _, v := range s {
		out = append(out, netip.MustParseAddr(v))
	}
	return out
}

// Lógica pura de los resolvers de Windows: solo adaptadores activos y no loopback, sin repetidos,
// sin los DNS «fantasma» fec0:0:0:ffff::1-3 ni direcciones sin especificar, IPv4 e IPv6 en orden.
func TestResolverHostsFiltra(t *testing.T) {
	as := []DNSAdapter{
		{Up: true, DNS: ips("192.0.2.53", "fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3")},
		{Up: false, DNS: ips("198.51.100.1")},
		{Up: true, Loopback: true, DNS: ips("127.0.0.1")},
		{Up: true, DNS: ips("192.0.2.53", "2001:db8::53", "0.0.0.0", "::", "fe80::1")},
	}
	got := ResolverHosts(as)
	want := []string{"192.0.2.53", "2001:db8::53"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResolverHosts = %v, quería %v", got, want)
	}
	if got := ResolverHosts(nil); len(got) != 0 {
		t.Fatalf("sin adaptadores debía quedar vacío: %v", got)
	}
}
