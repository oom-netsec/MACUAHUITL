package acl

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

var validName = regexp.MustCompile(`^[A-Za-z0-9_.:-]+$`)

// Generate escribe la ACL en la sintaxis del fabricante. Nunca la aplica.
// Una regla con varios puertos sueltos sale como "eq a b" solo en IOS (máximo 10);
// NX-OS y ASA no lo aceptan, así que ahí se escribe una línea por puerto o rango.
func Generate(vendor string, a ACL) (string, error) {
	if !validName.MatchString(a.Name) {
		return "", eerr("bad_name", "name", a.Name)
	}
	var addr func(netip.Prefix) string
	switch vendor {
	case "ios-xe":
		addr = iosAddrText
	case "nx-os":
		addr = nxAddrText
	case "asa":
		addr = asaAddrText
	default:
		return "", eerr("vendor", "vendor", vendor, "list", strings.Join(Vendors, ", "))
	}
	var lines []string
	for i, r := range a.Rules {
		r.SrcPorts, r.DstPorts = NormalizePorts(r.SrcPorts), NormalizePorts(r.DstPorts)
		if err := r.Validate(); err != nil {
			return "", ewrap("rule", err, "n", i+1)
		}
		if r.Established && vendor == "asa" {
			return "", eerr("asa_established", "n", i+1)
		}
		for _, v := range expand(vendor, r) {
			if v.Remark != "" {
				lines = append(lines, "remark "+v.Remark)
			}
			lines = append(lines, body(v, addr))
		}
	}
	var b strings.Builder
	switch vendor {
	case "ios-xe":
		fmt.Fprintf(&b, "ip access-list extended %s\n", a.Name)
		for _, l := range lines {
			fmt.Fprintf(&b, " %s\n", l)
		}
	case "nx-os":
		fmt.Fprintf(&b, "ip access-list %s\n", a.Name)
		for i, l := range lines {
			fmt.Fprintf(&b, "  %d %s\n", (i+1)*10, l)
		}
	case "asa":
		for _, l := range lines {
			if strings.HasPrefix(l, "remark ") {
				fmt.Fprintf(&b, "access-list %s %s\n", a.Name, l)
			} else {
				fmt.Fprintf(&b, "access-list %s extended %s\n", a.Name, l)
			}
		}
	}
	return b.String(), nil
}

// expand parte una regla en varias cuando su conjunto de puertos no cabe en un solo operador del fabricante.
func expand(vendor string, r Rule) []Rule {
	split := func(ps []PortRange) [][]PortRange {
		if _, ok := singleOp(ps); ok {
			return [][]PortRange{ps}
		}
		if vendor == "ios-xe" && len(ps) <= 10 && allSingle(ps) {
			return [][]PortRange{ps}
		}
		out := make([][]PortRange, 0, len(ps))
		for _, p := range ps {
			out = append(out, []PortRange{p})
		}
		return out
	}
	var out []Rule
	for _, sp := range split(r.SrcPorts) {
		for _, dp := range split(r.DstPorts) {
			v := r
			v.SrcPorts, v.DstPorts = sp, dp
			if len(out) > 0 {
				v.Remark = "" // el remark va una sola vez, antes de la primera línea
			}
			out = append(out, v)
		}
	}
	return out
}

func allSingle(ps []PortRange) bool {
	for _, p := range ps {
		if p.Lo != p.Hi {
			return false
		}
	}
	return true
}

func body(r Rule, addr func(netip.Prefix) string) string {
	parts := []string{r.Action.String(), r.Protocol, addr(r.Src)}
	parts = append(parts, strings.Fields(PortsText(r.SrcPorts))...)
	parts = append(parts, addr(r.Dst))
	parts = append(parts, strings.Fields(PortsText(r.DstPorts))...)
	if r.Established {
		parts = append(parts, "established")
	}
	if r.Log {
		parts = append(parts, "log")
	}
	return strings.Join(parts, " ")
}

// singleOp expresa el conjunto con un solo operador IOS, si se puede.
func singleOp(ps []PortRange) (string, bool) {
	ps = NormalizePorts(ps)
	switch {
	case len(ps) == 0:
		return "", true
	case len(ps) == 2 && ps[0].Lo == 0 && ps[1].Hi == 65535 && ps[0].Hi+2 == ps[1].Lo:
		return fmt.Sprintf("neq %d", ps[0].Hi+1), true
	case len(ps) == 1 && ps[0].Lo == ps[0].Hi:
		return fmt.Sprintf("eq %d", ps[0].Lo), true
	case len(ps) == 1 && ps[0].Hi == 65535:
		return fmt.Sprintf("gt %d", ps[0].Lo-1), true
	case len(ps) == 1 && ps[0].Lo == 0:
		return fmt.Sprintf("lt %d", ps[0].Hi+1), true
	case len(ps) == 1:
		return fmt.Sprintf("range %d %d", ps[0].Lo, ps[0].Hi), true
	}
	return "", false
}

// PortsText es la forma IOS del conjunto: un operador si cabe, o "eq a b c" / varios
// operadores seguidos si no. Es la misma forma que viaja por el contrato gRPC.
func PortsText(ps []PortRange) string {
	if s, ok := singleOp(ps); ok {
		return s
	}
	ps = NormalizePorts(ps)
	if allSingle(ps) {
		parts := []string{"eq"}
		for _, p := range ps {
			parts = append(parts, fmt.Sprint(p.Lo))
		}
		return strings.Join(parts, " ")
	}
	var parts []string
	for _, p := range ps {
		s, _ := singleOp([]PortRange{p})
		parts = append(parts, s)
	}
	return strings.Join(parts, " ")
}

func mask(p netip.Prefix) netip.Addr {
	m := uint32(0xffffffff) << (32 - p.Bits())
	if p.Bits() == 0 {
		m = 0
	}
	return netip.AddrFrom4([4]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)})
}

func wildcard(p netip.Prefix) netip.Addr {
	m := u32(mask(p))
	w := ^m
	return netip.AddrFrom4([4]byte{byte(w >> 24), byte(w >> 16), byte(w >> 8), byte(w)})
}

func iosAddrText(p netip.Prefix) string {
	switch p.Bits() {
	case 0:
		return "any"
	case 32:
		return "host " + p.Addr().String()
	}
	return p.Addr().String() + " " + wildcard(p).String()
}

func nxAddrText(p netip.Prefix) string {
	switch p.Bits() {
	case 0:
		return "any"
	case 32:
		return "host " + p.Addr().String()
	}
	return p.String()
}

func asaAddrText(p netip.Prefix) string {
	switch p.Bits() {
	case 0:
		return "any4"
	case 32:
		return "host " + p.Addr().String()
	}
	return p.Addr().String() + " " + mask(p).String()
}
