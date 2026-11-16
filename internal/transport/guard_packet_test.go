package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

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
	// Plazos: una lectura sin plazo cuelga el paquete entero si el datagrama no llega.
	srv.SetReadDeadline(time.Now().Add(5 * time.Second))
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, _ := srv.ReadFrom(buf)
	if string(buf[:n]) != "hola" {
		t.Fatal("no llegó")
	}
	// El servidor responde desde otro puerto: el socket sin conectar lo recibe.
	other, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer other.Close()
	// El socket del guard escucha en el comodín (0.0.0.0): en Windows enviar a 0.0.0.0 no es una dirección válida y el
	// datagrama se pierde en silencio; se envía a 127.0.0.1 con el mismo puerto.
	other.WriteTo([]byte("tid"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pc.LocalAddr().(*net.UDPAddr).Port})
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
