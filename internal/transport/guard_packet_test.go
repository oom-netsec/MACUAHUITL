package transport

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
)

func TestPacketToOnlyAuthorizedIP(t *testing.T) {
	var denied []audit.Entry
	g := NewGuard(nil, func(e audit.Entry) { denied = append(denied, e) })
	srv, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer srv.Close()
	port := uint16(srv.LocalAddr().(*net.UDPAddr).Port)
	if _, _, err := g.PacketTo(context.Background(), "j", "127.0.0.1", port); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("sin autorizar: %v", err)
	}
	g.Allow(context.Background(), "j", []string{"127.0.0.1"})
	pc, dst, err := g.PacketTo(context.Background(), "j", "127.0.0.1", port)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteTo([]byte("hola"), dst); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 10)
	n, _, _ := srv.ReadFrom(buf)
	if string(buf[:n]) != "hola" {
		t.Fatal("no llegó")
	}
	// El servidor responde desde otro puerto: el socket sin conectar lo recibe.
	other, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer other.Close()
	other.WriteTo([]byte("tid"), pc.LocalAddr())
	n, _, _ = pc.ReadFrom(buf)
	if string(buf[:n]) != "tid" {
		t.Fatal("respuesta desde otro puerto perdida")
	}
	// Enviar a otra IP, aunque sea la misma máquina, se rechaza.
	if _, err := pc.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 9}); !errors.Is(err, ErrEgressDenied) {
		t.Fatalf("destino no autorizado: %v", err)
	}
	g.Revoke("j")
	if _, _, err := g.PacketTo(context.Background(), "j", "127.0.0.1", port); !errors.Is(err, ErrEgressDenied) {
		t.Fatal("tras Revoke debe negar")
	}
	if len(denied) < 3 {
		t.Fatalf("denegaciones sin auditar: %v", denied)
	}
}
