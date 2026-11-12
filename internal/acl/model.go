// Package acl contiene el modelo neutral de ACLs, el parser de ACLs Cisco, el
// análisis de sombras y redundancias, y los generadores por fabricante (spec §13).
//
// No hace: aplicar ACLs a equipos; solo genera texto.
package acl

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type Action int

const (
	Permit Action = iota
	Deny
)

func (a Action) String() string {
	if a == Deny {
		return "deny"
	}
	return "permit"
}

// PortRange es un rango cerrado [Lo, Hi].
type PortRange struct{ Lo, Hi uint16 }

// Rule es una regla neutral: direcciones en CIDR (0.0.0.0/0 = any) y puertos como
// rangos; sin rangos = cualquier puerto.
type Rule struct {
	Action             Action
	Protocol           string // ip, tcp, udp, icmp o número
	Src, Dst           netip.Prefix
	SrcPorts, DstPorts []PortRange
	Log                bool
	Established        bool // solo tcp: tráfico de retorno (IOS/NX-OS); ASA no lo tiene
	Remark             string
}

type ACL struct {
	Name  string
	Rules []Rule
}

var Any = netip.MustParsePrefix("0.0.0.0/0")

var protocols = map[string]int{"ip": 0, "icmp": 1, "igmp": 2, "tcp": 6, "udp": 17, "gre": 47, "esp": 50, "ahp": 51, "ospf": 89, "pim": 103, "sctp": 132}

// ProtocolNumber resuelve nombres IOS y números.
func ProtocolNumber(name string) (int, bool) {
	if n, ok := protocols[name]; ok {
		return n, true
	}
	n, err := strconv.Atoi(name)
	return n, err == nil && n >= 0 && n <= 255
}

// Nombres de puerto más comunes en IOS/ASA; el resto se escribe numérico.
var portNames = map[string]uint16{
	"ftp-data": 20, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25, "domain": 53, "tftp": 69, "www": 80, "http": 80,
	"pop3": 110, "ntp": 123, "snmp": 161, "snmptrap": 162, "bgp": 179, "ldap": 389, "https": 443, "syslog": 514,
	"isakmp": 500, "non500-isakmp": 4500, "radius": 1812, "tacacs": 49, "bootps": 67, "bootpc": 68, "nfs": 2049, "rdp": 3389,
}

func parsePort(s string) (uint16, error) {
	if p, ok := portNames[s]; ok {
		return p, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("puerto %q inválido", s)
	}
	return uint16(n), nil
}

// ParsePorts convierte un operador IOS (eq, neq, gt, lt, range) en rangos.
func ParsePorts(op string, args ...string) ([]PortRange, error) {
	need := 1
	if op == "range" {
		need = 2
	}
	if len(args) != need {
		return nil, fmt.Errorf("%s necesita %d argumento(s)", op, need)
	}
	a, err := parsePort(args[0])
	if err != nil {
		return nil, err
	}
	switch op {
	case "eq":
		return []PortRange{{a, a}}, nil
	case "neq":
		var out []PortRange
		if a > 0 {
			out = append(out, PortRange{0, a - 1})
		}
		if a < 65535 {
			out = append(out, PortRange{a + 1, 65535})
		}
		return out, nil
	case "gt":
		if a == 65535 {
			return nil, errors.New("gt 65535 no coincide con ningún puerto")
		}
		return []PortRange{{a + 1, 65535}}, nil
	case "lt":
		if a == 0 {
			return nil, errors.New("lt 0 no coincide con ningún puerto")
		}
		return []PortRange{{0, a - 1}}, nil
	case "range":
		b, err := parsePort(args[1])
		if err != nil {
			return nil, err
		}
		if b < a {
			return nil, fmt.Errorf("range %d %d está vacío", a, b)
		}
		return []PortRange{{a, b}}, nil
	}
	return nil, fmt.Errorf("operador de puerto %q desconocido", op)
}

// CanonProtocol devuelve el nombre IOS de un protocolo dado por nombre o número ("6" → "tcp").
func CanonProtocol(s string) string {
	n, ok := ProtocolNumber(s)
	if !ok {
		return s
	}
	for name, num := range protocols {
		if num == n {
			return name
		}
	}
	return s
}

// NormalizePorts ordena y funde rangos contiguos o solapados; el conjunto completo
// (0–65535) se vuelve nil, que significa "cualquier puerto".
func NormalizePorts(ps []PortRange) []PortRange {
	if len(ps) == 0 {
		return nil
	}
	out := append([]PortRange(nil), ps...)
	sort.Slice(out, func(i, j int) bool { return out[i].Lo < out[j].Lo })
	merged := out[:1]
	for _, p := range out[1:] {
		last := &merged[len(merged)-1]
		if int(p.Lo) <= int(last.Hi)+1 {
			if p.Hi > last.Hi {
				last.Hi = p.Hi
			}
			continue
		}
		merged = append(merged, p)
	}
	if len(merged) == 1 && merged[0].Lo == 0 && merged[0].Hi == 65535 {
		return nil
	}
	return merged
}

func (r Rule) Validate() error {
	if _, ok := ProtocolNumber(r.Protocol); !ok {
		return fmt.Errorf("protocolo %q desconocido", r.Protocol)
	}
	if !r.Src.IsValid() || !r.Dst.IsValid() {
		return errors.New("origen y destino son obligatorios")
	}
	for _, p := range []netip.Prefix{r.Src, r.Dst} {
		if !p.Addr().Is4() {
			return fmt.Errorf("%s: solo IPv4 en esta versión", p)
		}
		if p != p.Masked() {
			return fmt.Errorf("%s tiene bits de host; usa %s", p, p.Masked())
		}
	}
	if strings.ContainsAny(r.Remark, "\r\n\x00") {
		return errors.New("el remark no puede tener saltos de línea")
	}
	proto := CanonProtocol(r.Protocol)
	if (len(r.SrcPorts) > 0 || len(r.DstPorts) > 0) && proto != "tcp" && proto != "udp" && proto != "sctp" {
		return fmt.Errorf("los puertos solo aplican a tcp/udp, no a %s", r.Protocol)
	}
	if r.Established && proto != "tcp" {
		return errors.New("established solo aplica a tcp")
	}
	for _, p := range append(append([]PortRange{}, r.SrcPorts...), r.DstPorts...) {
		if p.Hi < p.Lo {
			return fmt.Errorf("rango de puertos %d-%d vacío", p.Lo, p.Hi)
		}
	}
	return nil
}
