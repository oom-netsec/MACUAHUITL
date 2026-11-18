package resolve

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func fakeLookup(t *testing.T, addrs ...string) {
	t.Helper()
	old := Lookup
	Lookup = func(_ context.Context, _, _ string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
	t.Cleanup(func() { Lookup = old })
}

func TestTarget(t *testing.T) {
	for _, c := range []struct {
		name, host, fam string
		addrs           []string
		want            string
		ok              bool
	}{
		{"v4 por family", "sw1.example", "4", []string{"2001:db8::1", "192.0.2.1"}, "192.0.2.1", true},
		{"v6 por family", "sw1.example", "6", []string{"192.0.2.1", "2001:db8::1"}, "2001:db8::1", true},
		{"family vacío: el primero tal cual", "sw1.example", "", []string{"2001:db8::1", "192.0.2.1"}, "2001:db8::1", true},
		{"sin la familia pedida", "sw1.example", "6", []string{"192.0.2.1"}, "", false},
		{"IP intacta", "192.0.2.7", "", nil, "192.0.2.7", true},
		{"IPv6 con zona intacta", "fe80::1%eth0", "6", nil, "fe80::1%eth0", true},
	} {
		fakeLookup(t, c.addrs...)
		got, ok := Target(context.Background(), c.host, c.fam)
		if got != c.want || ok != c.ok {
			t.Errorf("%s: %q,%v; quería %q,%v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestTargetFallaNoResuelve(t *testing.T) {
	old := Lookup
	Lookup = func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	t.Cleanup(func() { Lookup = old })
	if got, ok := Target(context.Background(), "mdns.local", ""); ok || got != "" {
		t.Errorf("quería vacío y false, llegó %q,%v", got, ok)
	}
}
