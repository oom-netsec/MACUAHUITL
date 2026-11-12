package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
)

func udpEcho(t *testing.T) (string, uint16) {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		b := make([]byte, 512)
		for {
			n, a, err := c.ReadFrom(b)
			if err != nil {
				return
			}
			c.WriteTo(b[:n], a)
		}
	}()
	ap := netip.MustParseAddrPort(c.LocalAddr().String())
	return ap.Addr().String(), ap.Port()
}

func TestDialNetworkUDP(t *testing.T) {
	host, port := udpEcho(t)
	g := NewGuard(nil, nil)
	g.Allow(context.Background(), "r", []string{host})
	c, err := g.DialNetwork(context.Background(), "r", "udp", host, port)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("hola"))
	b := make([]byte, 8)
	n, _ := c.Read(b)
	if string(b[:n]) != "hola" {
		t.Fatalf("echo = %q", b[:n])
	}
	if _, err := g.DialNetwork(context.Background(), "otro", "udp", host, port); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("other run: %v", err)
	}
	if _, err := g.DialNetwork(context.Background(), "r", "unix", host, port); err == nil {
		t.Fatal("unix network accepted")
	}
}

func TestAllowAnyOnPorts(t *testing.T) {
	host, port := udpEcho(t)
	var denied []audit.Entry
	g := NewGuard(nil, func(e audit.Entry) { denied = append(denied, e) })
	g.AllowAnyOnPorts("dns-profundo", []uint16{port})
	if c, err := g.DialNetwork(context.Background(), "dns-profundo", "udp", host, port); err != nil {
		t.Fatalf("allowed port denied: %v", err)
	} else {
		c.Close()
	}
	if _, err := g.DialNetwork(context.Background(), "dns-profundo", "udp", host, port+1); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("other port allowed: %v", err)
	}
	if _, err := g.Dial(context.Background(), "dns-profundo", host, 22); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("ssh allowed by a DNS-only policy: %v", err)
	}
	if len(denied) != 2 {
		t.Fatalf("denials audited = %d", len(denied))
	}
	g.Revoke("dns-profundo")
	if _, err := g.DialNetwork(context.Background(), "dns-profundo", "udp", host, port); !errors.Is(err, ErrEgressDenied) {
		t.Fatal("revoke did not clear the port policy")
	}
}
