package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
)

func listener(t *testing.T) (string, uint16) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	ap := netip.MustParseAddrPort(l.Addr().String())
	return ap.Addr().String(), ap.Port()
}

func fakeResolver(m map[string][]string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, s := range m[host] {
			out = append(out, netip.MustParseAddr(s))
		}
		if len(out) == 0 {
			return nil, errors.New("no such host")
		}
		return out, nil
	}
}

func TestDialAllowedIP(t *testing.T) {
	host, port := listener(t)
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{host}); err != nil {
		t.Fatal(err)
	}
	c, err := g.Dial(context.Background(), "j", host, port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestDialDenied(t *testing.T) {
	host, port := listener(t)
	var denied []audit.Entry
	g := NewGuard(nil, func(e audit.Entry) { denied = append(denied, e) })
	if _, err := g.Dial(context.Background(), "j", host, port); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("err = %v", err)
	}
	if len(denied) != 1 || denied[0].Target != net.JoinHostPort(host, fmt.Sprint(port)) || denied[0].Action != "egress.denied" || denied[0].Detail != "j tcp" {
		t.Fatalf("denied = %+v", denied)
	}
}

func TestOtherJobCannotUse(t *testing.T) {
	host, port := listener(t)
	g := NewGuard(nil, nil)
	g.Allow(context.Background(), "j1", []string{host})
	if _, err := g.Dial(context.Background(), "j2", host, port); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("err = %v", err)
	}
}

func TestCIDR(t *testing.T) {
	host, port := listener(t)
	g := NewGuard(nil, nil)
	g.Allow(context.Background(), "a", []string{"127.0.0.0/30"})
	g.Allow(context.Background(), "b", []string{"10.0.0.0/30"})
	if c, err := g.Dial(context.Background(), "a", host, port); err != nil {
		t.Fatalf("a: %v", err)
	} else {
		c.Close()
	}
	if _, err := g.Dial(context.Background(), "b", host, port); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("b: %v", err)
	}
}

func TestNameMultipleIPs(t *testing.T) {
	g := NewGuard(fakeResolver(map[string][]string{"sw1": {"127.0.0.1", "127.0.0.2"}}), nil)
	if err := g.Allow(context.Background(), "j", []string{"sw1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Dial(context.Background(), "j", "127.0.0.2", 1); errors.Is(err, ErrEgressDenied) {
		t.Fatalf("127.0.0.2 should be authorized: %v", err)
	}
	if _, err := g.Dial(context.Background(), "j", "127.0.0.3", 1); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("127.0.0.3: %v", err)
	}
}

func TestDialByAllowedName(t *testing.T) {
	host, port := listener(t)
	g := NewGuard(fakeResolver(map[string][]string{"sw1": {host}}), nil)
	g.Allow(context.Background(), "j", []string{"sw1"})
	c, err := g.Dial(context.Background(), "j", "sw1", port)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestAllowInvalidAddress(t *testing.T) {
	g := NewGuard(fakeResolver(nil), nil)
	for _, a := range []string{"", "10.0.0.0/33", "no-existe"} {
		if err := g.Allow(context.Background(), "j", []string{a}); err == nil {
			t.Errorf("Allow(%q) should fail", a)
		}
	}
}

func TestRevoke(t *testing.T) {
	host, port := listener(t)
	g := NewGuard(nil, nil)
	g.Allow(context.Background(), "j", []string{host})
	g.Revoke("j")
	if _, err := g.Dial(context.Background(), "j", host, port); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("err = %v", err)
	}
}
