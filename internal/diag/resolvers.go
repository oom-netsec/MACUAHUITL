package diag

import "net/netip"

// DNSAdapter es un adaptador de red con los servidores DNS que tiene configurados.
type DNSAdapter struct {
	Up, Loopback bool
	DNS          []netip.Addr
}

// ResolverHosts devuelve los DNS de los adaptadores activos y no loopback, sin repetidos y en orden.
// Descarta lo que Windows reporta sin estar configurado: direcciones sin especificar, link-local sin zona
// y fec0::/10 (los «fantasma» fec0:0:0:ffff::1-3).
func ResolverHosts(as []DNSAdapter) []string {
	seen := map[netip.Addr]bool{}
	var out []string
	for _, a := range as {
		if !a.Up || a.Loopback {
			continue
		}
		for _, ip := range a.DNS {
			ip = ip.Unmap()
			if !ip.IsValid() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || seen[ip] {
				continue
			}
			if ip.Is6() && ip.As16()[0] == 0xfe && ip.As16()[1]&0xc0 == 0xc0 { // fec0::/10 (site-local, en desuso)
				continue
			}
			seen[ip] = true
			out = append(out, ip.String())
		}
	}
	return out
}
