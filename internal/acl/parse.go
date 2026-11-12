package acl

import (
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// LineError señala la línea del texto importado que no se entendió. Msg es el motivo en español y Err el mismo
// motivo con su código del catálogo (también es un i18n.Coded: con en, el mensaje sale en inglés).
type LineError struct {
	Line int
	Msg  string
	Err  error
}

func (e *LineError) Error() string { return fmt.Sprintf("línea %d: %s", e.Line, e.Msg) }

// Reason, Metadata y Localize lo vuelven un i18n.Coded.
func (e *LineError) Reason() string { return i18n.Reason("acl.err.line") }
func (e *LineError) Metadata() map[string]string {
	return i18n.Metadata("acl.err.line", i18n.A("line", e.Line))
}
func (e *LineError) Localize(loc string) string {
	return i18n.Wrap("acl.err.line", e.Err, i18n.A("line", e.Line)).Localize(loc)
}

// lineErr arma el error de la línea n con su motivo.
func lineErr(n int, cause error) *LineError {
	return &LineError{Line: n, Msg: cause.Error(), Err: cause}
}

func eerr(code string, kv ...any) error { return i18n.New("acl.err."+code, i18n.A(kv...)) }

func ewrap(code string, cause error, kv ...any) error {
	return i18n.Wrap("acl.err."+code, cause, i18n.A(kv...))
}

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
		return ACL{}, eerr("vendor", "vendor", vendor, "list", strings.Join(Vendors, ", "))
	}
	var out ACL
	var remarks []string
	// setName rechaza una segunda ACL en el mismo texto: se mezclarían las reglas.
	setName := func(name string, line int) error {
		if out.Name != "" && out.Name != name {
			return lineErr(line, eerr("other_acl", "name", name))
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
				return ACL{}, lineErr(n, eerr("std_acl"))
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
				return ACL{}, lineErr(n, eerr("fragments"))
			}
			body = seqPrefix.ReplaceAllString(line, "")
		case "asa":
			m := asaLine.FindStringSubmatch(line)
			if m == nil {
				return ACL{}, lineErr(n, eerr("asa_form"))
			}
			if err := setName(m[1], n); err != nil {
				return ACL{}, err
			}
			body = strings.TrimPrefix(m[2], "extended ")
		}
		if out.Name == "" {
			return ACL{}, lineErr(n, eerr("no_header"))
		}
		if r, ok := strings.CutPrefix(body, "remark "); ok {
			remarks = append(remarks, strings.TrimSpace(r))
			continue
		}
		rule, err := parseRule(strings.Fields(body), addr)
		if err != nil {
			return ACL{}, lineErr(n, err)
		}
		rule.Remark, remarks = strings.Join(remarks, " / "), nil
		out.Rules = append(out.Rules, rule)
	}
	if out.Name == "" {
		return ACL{}, lineErr(1, eerr("none"))
	}
	return out, nil
}

var portOps = map[string]bool{"eq": true, "neq": true, "gt": true, "lt": true, "range": true}

// parseRule entiende: (permit|deny) PROTO ORIGEN [puertos] DESTINO [puertos] [log|log-input] [established]
func parseRule(t []string, addr func([]string) (netip.Prefix, int, error)) (Rule, error) {
	if len(t) < 2 {
		return Rule{}, eerr("incomplete")
	}
	var r Rule
	switch t[0] {
	case "permit":
		r.Action = Permit
	case "deny":
		r.Action = Deny
	default:
		return Rule{}, eerr("expect_action", "got", t[0])
	}
	if _, ok := ProtocolNumber(t[1]); !ok {
		return Rule{}, eerr("bad_proto", "proto", t[1])
	}
	r.Protocol = CanonProtocol(t[1])
	t = t[2:]
	var err error
	if r.Src, t, err = addrAndPorts(t, addr, &r.SrcPorts); err != nil {
		return Rule{}, ewrap("src", err)
	}
	if r.Dst, t, err = addrAndPorts(t, addr, &r.DstPorts); err != nil {
		return Rule{}, ewrap("dst", err)
	}
	for _, flag := range t {
		switch flag {
		case "log", "log-input", "log-default":
			r.Log = true
		case "established":
			r.Established = true
		default:
			return Rule{}, eerr("unknown_flag", "flag", flag)
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
		return netip.Prefix{}, nil, eerr("no_address")
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
			return netip.Prefix{}, nil, eerr("no_args", "op", op)
		}
		args := t[:n]
		t = t[n:]
		if op == "neq" && len(t) > 0 {
			if _, perr := parsePort(t[0]); perr == nil {
				return netip.Prefix{}, nil, eerr("neq_multi")
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
		return netip.Addr{}, eerr("bad_ipv4", "addr", s)
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
		return netip.Prefix{}, eerr("wild_noncontig", "wild", wild)
	}
	return netip.PrefixFrom(net, 32-bits.OnesCount32(w)).Masked(), nil
}

// netmaskPrefix convierte "red máscara" (ASA) en CIDR; la máscara debe ser 1…10…0.
func netmaskPrefix(net, mask netip.Addr) (netip.Prefix, error) {
	m := u32(mask)
	if (^m)&(^m+1) != 0 {
		return netip.Prefix{}, eerr("mask_noncontig", "mask", mask)
	}
	return netip.PrefixFrom(net, bits.OnesCount32(m)).Masked(), nil
}

func hostOrAny(t []string) (netip.Prefix, int, bool, error) {
	switch t[0] {
	case "any", "any4":
		return Any, 1, true, nil
	case "host":
		if len(t) < 2 {
			return netip.Prefix{}, 0, true, eerr("host_no_addr")
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
		return netip.Prefix{}, 0, eerr("no_wildcard")
	}
	a, err := ip4(t[0])
	if err != nil {
		return netip.Prefix{}, 0, err
	}
	w, err := ip4(t[1])
	if err != nil {
		return netip.Prefix{}, 0, ewrap("wildcard", err)
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
			return netip.Prefix{}, 0, eerr("bad_prefix", "prefix", t[0])
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
		return netip.Prefix{}, 0, eerr("no_mask")
	}
	a, err := ip4(t[0])
	if err != nil {
		return netip.Prefix{}, 0, err
	}
	m, err := ip4(t[1])
	if err != nil {
		return netip.Prefix{}, 0, ewrap("mask", err)
	}
	p, err := netmaskPrefix(a, m)
	return p, 2, err
}
