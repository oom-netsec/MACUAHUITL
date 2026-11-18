package resolve

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Lookup es el resolvedor; las pruebas lo reemplazan. En Windows usa GetAddrInfoW; en Linux sin cgo, el DNS de Go.
var Lookup = net.DefaultResolver.LookupNetIP

// Target resuelve el destino una sola vez para pasarle a ping o traceroute la IP y no el nombre.
// Una IP (con zona incluida) vuelve intacta. Con family «4» o «6» toma la primera de esa familia; vacía, la
// primera tal como llega (Go ya la ordena según RFC 6724). Si no resuelve devuelve ("", false): el llamador deja
// el nombre y la herramienta lo resuelve como siempre (mDNS y otros módulos NSS que Go no usa sin cgo).
func Target(ctx context.Context, host, family string) (string, bool) {
	if _, err := netip.ParseAddr(host); err == nil {
		return host, true
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := Lookup(ctx, "ip", host)
	if err != nil {
		return "", false
	}
	for _, a := range addrs {
		a = a.Unmap()
		if family == "" || family == "4" && a.Is4() || family == "6" && a.Is6() {
			return a.String(), true
		}
	}
	return "", false
}
