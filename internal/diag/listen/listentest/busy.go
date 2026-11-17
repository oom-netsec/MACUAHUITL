// Package listentest abre puertos ocupados para las pruebas de los servicios (que no pueden importar net: noegress).
package listentest

import (
	"net"
	"testing"
)

// Busy ocupa un puerto libre de 127.0.0.1 ("tcp" o "udp") hasta que termine la prueba y devuelve su "IP:puerto".
func Busy(t testing.TB, network string) string {
	t.Helper()
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { pc.Close() })
		return pc.LocalAddr().String()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}
