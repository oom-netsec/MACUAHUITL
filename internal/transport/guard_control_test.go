package transport

import (
	"context"
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
)

// Control filtra en el último paso, cuando una librería marca por su cuenta (gosnmp).
func TestControlFiltraDestino(t *testing.T) {
	host, port := udpEcho(t)
	var denied []audit.Entry
	g := NewGuard(nil, func(e audit.Entry) { denied = append(denied, e) })
	g.Allow(context.Background(), "r", []string{host})
	d := net.Dialer{Control: g.Control("r")}
	c, err := d.Dial("udp", net.JoinHostPort(host, itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	d = net.Dialer{Control: g.Control("otro")}
	if _, err := d.Dial("udp", net.JoinHostPort(host, itoa(port))); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("otro run: %v", err)
	}
	if len(denied) != 1 || denied[0].Action != "egress.denied" {
		t.Fatalf("auditoría = %+v", denied)
	}
	g.AllowAnyOnPorts("p", []uint16{port})
	d = net.Dialer{Control: g.Control("p")}
	if c, err := d.Dial("udp", net.JoinHostPort(host, itoa(port))); err != nil {
		t.Fatalf("política por puertos: %v", err)
	} else {
		c.Close()
	}
}

func itoa(p uint16) string { return strconv.Itoa(int(p)) }
