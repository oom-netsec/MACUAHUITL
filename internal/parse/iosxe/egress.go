package iosxe

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// ParseEgress lee la salida de `show ip cef <ip>` o de `show ip route <ip>` (y sus versiones `ipv6`) y devuelve las interfaces por las que sale el tráfico hacia esa
// dirección (todas, si hay varias rutas de igual costo). ok=false si no hay certeza: sin tabla, Null0, un salto sin interfaz (recursivo) o
// una salida que no se reconoce.
//
// Formatos (de la documentación de Cisco, sin validar en laboratorio): CEF de IOS 15.2 (`via IP, Vlan10, 0 dependencies`, `via Vlan99, 0
// dependencies`), CEF de IOS-XE (`nexthop IP Vlan10`, `attached to Vlan99`) y la ruta (`* IP, from ..., via Vlan10`, `* directly connected,
// via Vlan99`).
func ParseEgress(text string) ([]string, bool) {
	var out []string
	sure := true
	add := func(name string) {
		if name == "" || strings.HasPrefix(strings.ToLower(name), "null") {
			sure = false
			return
		}
		if n := ShortIf(name); !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	for _, ln := range lines(text) {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "%"):
			return nil, false
		case strings.HasPrefix(t, "nexthop "):
			f := strings.Fields(t)
			if len(f) < 3 {
				sure = false
			} else {
				add(f[2])
			}
		case strings.HasPrefix(t, "attached to "):
			add(strings.TrimSpace(strings.TrimPrefix(t, "attached to ")))
		case strings.HasPrefix(t, "via "):
			f := strings.Split(strings.TrimPrefix(t, "via "), ",")
			if _, err := netip.ParseAddr(strings.TrimSpace(f[0])); err != nil { // via Vlan99, 0 dependencies
				add(strings.TrimSpace(f[0]))
			} else if len(f) > 1 && interfaceLike(strings.TrimSpace(f[1])) { // via 10.1.1.2, Vlan10, 0 dependencies
				add(strings.TrimSpace(f[1]))
			} else {
				sure = false // recursivo: el salto se resuelve por otra ruta
			}
		case egressV6HopRe.MatchString(t): // IPv6: `directly connected, Vlan99` o `FE80::1, Vlan10`; sin interfaz es recursivo
			if m := egressV6HopRe.FindStringSubmatch(t); m[1] != "" {
				add(m[1])
			} else {
				sure = false
			}
		case egressHopRe.MatchString(t):
			if m := egressViaRe.FindStringSubmatch(t); m != nil {
				add(m[1])
			} else {
				sure = false
			}
		}
	}
	if !sure || len(out) == 0 {
		return nil, false
	}
	return out, true
}

var (
	// Línea de un salto de `show ip route <ip>`: `* 10.10.0.2, from ...` o `* directly connected, via Vlan99`.
	egressHopRe = regexp.MustCompile(`^\*?\s*(?:directly connected|\d+\.\d+\.\d+\.\d+)(?:[,\s]|$)`)
	// Salto de `show ipv6 route <ip>` bajo `Routing paths:`: la dirección (o `directly connected`) y, si la hay, la interfaz.
	egressV6HopRe = regexp.MustCompile(`^(?:directly connected|[0-9A-Fa-f]*:[0-9A-Fa-f:.]*)(?:,\s*([A-Za-z][A-Za-z-]*\d[\d/.:]*))?$`)
	egressViaRe   = regexp.MustCompile(`, via (\S+)$`)
	ifaceLikeRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z-]*\d[\d/.:]*$`)
)

func interfaceLike(s string) bool { return ifaceLikeRe.MatchString(s) }

// RoutingOff dice si la salida de `show ip route` es la de un equipo con el enrutamiento apagado (un switch L2): `Default gateway is X` o
// `IP routing not enabled`. Formato de la documentación de IOS 15.2E, sin validar en laboratorio.
func RoutingOff(text string) bool {
	for _, ln := range lines(text) {
		t := strings.ToLower(strings.TrimSpace(ln))
		if strings.HasPrefix(t, "default gateway is") || strings.Contains(t, "ip routing not enabled") {
			return true
		}
	}
	return false
}
