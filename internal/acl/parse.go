package acl

import (
	"errors"
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"strings"
)

// LineError señala la línea del texto importado que no se entendió.
type LineError struct {
	Line int
	Msg  string
}

func (e *LineError) Error() string { return fmt.Sprintf("línea %d: %s", e.Line, e.Msg) }

var Vendors = []string{"ios-xe", "nx-os", "asa"}

var (
	iosHeader = regexp.MustCompile(`^ip access-list (?:extended )?(\S+)$`)
	// Numeradas estándar: 1–99 y 1300–1999. Extendidas: 100–199 y 2000–2699.
	iosStandard = regexp.MustCompile(`^(?:ip access-list standard |access-list (?:[1-9]|[1-9][0-9]|1[3-9][0-9][0-9]) )`)
	iosNumbered = regexp.MustCompile(`^access-list (\d+) (.*)$`)
	nxHeader    = regexp.MustCompile(`^ip access-list (\S+)$`)
	asaLine     = regexp.MustCompile(`^access-list (\S+) (?:line \d+ )?(remark .*|extended .*)$`)
	seqPrefix   = regexp.MustCompile(`^\d+ `)
)

// Parse importa una ACL del fabricante dado. El texto puede traer ruido de "show run".
func Parse(vendor, text string) (ACL, error) {
	var addr func([]string) (netip.Prefix, int, error)
	switch vendor {
	case "ios-xe":
		addr = iosAddr
	case "nx-os":
		addr = nxAddr
	case "asa":
		addr = asaAddr
	default:
		return ACL{}, fmt.Errorf("acl: fabricante %q no soportado (%s)", vendor, strings.Join(Vendors, ", "))
	}
	var out ACL
	var remarks []string
	// setName rechaza una segunda ACL en el mismo texto: se mezclarían las reglas.
	setName := func(name string, line int) error {
		if out.Name != "" && out.Name != name {
			return &LineError{line, fmt.Sprintf("el texto trae otra ACL (%s); importa una a la vez", name)}
		}
		out.Name = name
		return nil
	}
	for i, raw := range strings.Split(text, "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "#") || line == "end" || strings.HasPrefix(line, "Building") || strings.HasPrefix(line, "Current") {
			continue
		}
		body := ""
		switch vendor {
		case "ios-xe":
			if iosStandard.MatchString(line) {
				return ACL{}, &LineError{n, "ACL estándar no soportada; usa una extendida"}
			}
			if m := iosHeader.FindStringSubmatch(line); m != nil {
				if err := setName(m[1], n); err != nil {
					return ACL{}, err
				}
				continue
			}
			if m := iosNumbered.FindStringSubmatch(line); m != nil {
				if err := setName(m[1], n); err != nil {
					return ACL{}, err
				}
				body = m[2]
			} else {
				body = seqPrefix.ReplaceAllString(line, "")
			}
		case "nx-os":
			if m := nxHeader.FindStringSubmatch(line); m != nil {
				if err := setName(m[1], n); err != nil {
					return ACL{}, err
				}
				continue
			}
			if strings.HasPrefix(line, "statistics") {
				continue
			}
			if strings.HasPrefix(line, "fragments") {
				return ACL{}, &LineError{n, "'fragments' cambia el trato de fragmentos y no se puede traducir; quítalo o tradúcelo a mano"}
			}
			body = seqPrefix.ReplaceAllString(line, "")
		case "asa":
			m := asaLine.FindStringSubmatch(line)
			if m == nil {
				return ACL{}, &LineError{n, "se esperaba 'access-list NOMBRE extended …' o 'remark …'"}
			}
			if err := setName(m[1], n); err != nil {
				return ACL{}, err
			}
			body = strings.TrimPrefix(m[2], "extended ")
		}
		if out.Name == "" {
			return ACL{}, &LineError{n, "falta el encabezado de la ACL"}
		}
		if r, ok := strings.CutPrefix(body, "remark "); ok {
			remarks = append(remarks, strings.TrimSpace(r))
			continue
		}
		rule, err := parseRule(strings.Fields(body), addr)
		if err != nil {
			return ACL{}, &LineError{n, err.Error()}
		}
		rule.Remark, remarks = strings.Join(remarks, " / "), nil
		out.Rules = append(out.Rules, rule)
	}
	if out.Name == "" {
		return ACL{}, &LineError{1, "no se encontró ninguna ACL"}
	}
	return out, nil
}

var portOps = map[string]bool{"eq": true, "neq": true, "gt": true, "lt": true, "range": true}

// parseRule entiende: (permit|deny) PROTO ORIGEN [puertos] DESTINO [puertos] [log|log-input] [established]
func parseRule(t []string, addr func([]string) (netip.Prefix, int, error)) (Rule, error) {
	if len(t) < 2 {
		return Rule{}, errors.New("regla incompleta")
	}
	var r Rule
	switch t[0] {
	case "permit":
		r.Action = Permit
	case "deny":
		r.Action = Deny
	default:
		return Rule{}, fmt.Errorf("se esperaba permit o deny, no %q", t[0])
	}
	if _, ok := ProtocolNumber(t[1]); !ok {
		return Rule{}, fmt.Errorf("protocolo %q desconocido", t[1])
	}
	r.Protocol = CanonProtocol(t[1])
	t = t[2:]
	var err error
	if r.Src, t, err = addrAndPorts(t, addr, &r.SrcPorts); err != nil {
		return Rule{}, fmt.Errorf("origen: %w", err)
	}
	if r.Dst, t, err = addrAndPorts(t, addr, &r.DstPorts); err != nil {
		return Rule{}, fmt.Errorf("destino: %w", err)
	}
	for _, flag := range t {
		switch flag {
		case "log", "log-input", "log-default":
			r.Log = true
		case "established":
			r.Established = true
		default:
			return Rule{}, fmt.Errorf("no se entiende %q (tipos ICMP, time-range y objetos no están soportados todavía)", flag)
		}
	}
	r.SrcPorts, r.DstPorts = NormalizePorts(r.SrcPorts), NormalizePorts(r.DstPorts)
	if err := r.Validate(); err != nil {
		return Rule{}, err
	}
	return r, nil
}

func addrAndPorts(t []string, addr func([]string) (netip.Prefix, int, error), ports *[]PortRange) (netip.Prefix, []string, error) {
	if len(t) == 0 {
		return netip.Prefix{}, nil, errors.New("falta la dirección")
	}
	p, used, err := addr(t)
	if err != nil {
		return netip.Prefix{}, nil, err
	}
	t = t[used:]
	if len(t) > 0 && portOps[t[0]] {
		op := t[0]
		t = t[1:]
		n := 1
		if op == "range" {
			n = 2
		}
		if len(t) < n {
			return netip.Prefix{}, nil, fmt.Errorf("%s sin argumentos", op)
		}
		args := t[:n]
		t = t[n:]
		if op == "neq" && len(t) > 0 {
			if _, perr := parsePort(t[0]); perr == nil {
				return netip.Prefix{}, nil, errors.New("neq con varios puertos no tiene una traducción segura; escribe una regla por puerto")
			}
		}
		// IOS admite "eq 80 443": se consumen más puertos mientras lo sean.
		for op == "eq" && len(t) > 0 {
			if _, perr := parsePort(t[0]); perr != nil {
				break
			}
			args = append(args, t[0])
			t = t[1:]
		}
		for i, a := range args {
			if op == "range" && i > 0 {
				break
			}
			var pr []PortRange
			if op == "range" {
				pr, err = ParsePorts(op, args...)
			} else {
				pr, err = ParsePorts(op, a)
			}
			if err != nil {
				return netip.Prefix{}, nil, err
			}
			*ports = append(*ports, pr...)
		}
	}
	return p, t, nil
}

func ip4(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, fmt.Errorf("dirección IPv4 %q inválida", s)
	}
	return a, nil
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// wildcardPrefix convierte "red wildcard" (IOS/NX-OS) en CIDR; la wildcard debe ser 0…01…1.
func wildcardPrefix(net, wild netip.Addr) (netip.Prefix, error) {
	w := u32(wild)
	if w&(w+1) != 0 {
		return netip.Prefix{}, fmt.Errorf("wildcard %s no es contigua; no se puede expresar como CIDR", wild)
	}
	return netip.PrefixFrom(net, 32-bits.OnesCount32(w)).Masked(), nil
}

// netmaskPrefix convierte "red máscara" (ASA) en CIDR; la máscara debe ser 1…10…0.
func netmaskPrefix(net, mask netip.Addr) (netip.Prefix, error) {
	m := u32(mask)
	if (^m)&(^m+1) != 0 {
		return netip.Prefix{}, fmt.Errorf("máscara %s no es contigua", mask)
	}
	return netip.PrefixFrom(net, bits.OnesCount32(m)).Masked(), nil
}

func hostOrAny(t []string) (netip.Prefix, int, bool, error) {
	switch t[0] {
	case "any", "any4":
		return Any, 1, true, nil
	case "host":
		if len(t) < 2 {
			return netip.Prefix{}, 0, true, errors.New("host sin dirección")
		}
		a, err := ip4(t[1])
		if err != nil {
			return netip.Prefix{}, 0, true, err
		}
		return netip.PrefixFrom(a, 32), 2, true, nil
	}
	return netip.Prefix{}, 0, false, nil
}

func iosAddr(t []string) (netip.Prefix, int, error) {
	if p, n, done, err := hostOrAny(t); done {
		return p, n, err
	}
	if len(t) < 2 {
		return netip.Prefix{}, 0, errors.New("falta la wildcard")
	}
	a, err := ip4(t[0])
	if err != nil {
		return netip.Prefix{}, 0, err
	}
	w, err := ip4(t[1])
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("wildcard: %w", err)
	}
	p, err := wildcardPrefix(a, w)
	return p, 2, err
}

func nxAddr(t []string) (netip.Prefix, int, error) {
	if p, n, done, err := hostOrAny(t); done {
		return p, n, err
	}
	if strings.Contains(t[0], "/") {
		p, err := netip.ParsePrefix(t[0])
		if err != nil || !p.Addr().Is4() {
			return netip.Prefix{}, 0, fmt.Errorf("prefijo %q inválido", t[0])
		}
		return p.Masked(), 1, nil
	}
	return iosAddr(t)
}

func asaAddr(t []string) (netip.Prefix, int, error) {
	if p, n, done, err := hostOrAny(t); done {
		return p, n, err
	}
	if len(t) < 2 {
		return netip.Prefix{}, 0, errors.New("falta la máscara")
	}
	a, err := ip4(t[0])
	if err != nil {
		return netip.Prefix{}, 0, err
	}
	m, err := ip4(t[1])
	if err != nil {
		return netip.Prefix{}, 0, fmt.Errorf("máscara: %w", err)
	}
	p, err := netmaskPrefix(a, m)
	return p, 2, err
}
