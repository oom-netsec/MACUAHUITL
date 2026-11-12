package radiustest

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"unicode"
	"unicode/utf8"
)

type kind int

const (
	kText kind = iota
	kInt
	kIP
	kOctets
	kTaggedInt  // Tunnel-Type, Tunnel-Medium-Type: etiqueta + entero de 24 bits (RFC 2868)
	kTaggedText // Tunnel-Private-Group-ID: etiqueta opcional + texto
	kSecret     // nunca se muestra el contenido
)

type def struct {
	name  string
	kind  kind
	enums map[uint32]string
}

var serviceTypes = map[uint32]string{1: "Login", 2: "Framed", 3: "Callback-Login", 4: "Callback-Framed", 5: "Outbound",
	6: "Administrative", 7: "NAS-Prompt", 8: "Authenticate-Only", 10: "Call-Check"}

var nasPortTypes = map[uint32]string{0: "Async", 1: "Sync", 2: "ISDN", 5: "Virtual", 15: "Ethernet", 19: "Wireless-802.11"}

var dict = map[byte]def{
	1: {"User-Name", kText, nil}, 2: {"User-Password", kSecret, nil}, 3: {"CHAP-Password", kSecret, nil},
	4: {"NAS-IP-Address", kIP, nil}, 5: {"NAS-Port", kInt, nil}, 6: {"Service-Type", kInt, serviceTypes},
	7: {"Framed-Protocol", kInt, map[uint32]string{1: "PPP", 2: "SLIP"}}, 8: {"Framed-IP-Address", kIP, nil},
	9: {"Framed-IP-Netmask", kIP, nil}, 11: {"Filter-Id", kText, nil}, 12: {"Framed-MTU", kInt, nil},
	18: {"Reply-Message", kText, nil}, 24: {"State", kOctets, nil}, 25: {"Class", kOctets, nil},
	27: {"Session-Timeout", kInt, nil}, 28: {"Idle-Timeout", kInt, nil},
	29: {"Termination-Action", kInt, map[uint32]string{0: "Default", 1: "RADIUS-Request"}},
	30: {"Called-Station-Id", kText, nil}, 31: {"Calling-Station-Id", kText, nil}, 32: {"NAS-Identifier", kText, nil},
	33: {"Proxy-State", kOctets, nil},
	40: {"Acct-Status-Type", kInt, map[uint32]string{1: "Start", 2: "Stop", 3: "Interim-Update", 7: "Accounting-On", 8: "Accounting-Off"}},
	44: {"Acct-Session-Id", kText, nil}, 46: {"Acct-Session-Time", kInt, nil}, 60: {"CHAP-Challenge", kOctets, nil},
	61: {"NAS-Port-Type", kInt, nasPortTypes},
	64: {"Tunnel-Type", kTaggedInt, map[uint32]string{3: "L2TP", 13: "VLAN"}},
	65: {"Tunnel-Medium-Type", kTaggedInt, map[uint32]string{1: "IPv4", 2: "IPv6", 6: "802"}},
	79: {"EAP-Message", kOctets, nil}, 80: {"Message-Authenticator", kOctets, nil},
	81: {"Tunnel-Private-Group-ID", kTaggedText, nil}, 85: {"Acct-Interim-Interval", kInt, nil},
	87: {"NAS-Port-Id", kText, nil}, 101: {"Error-Cause", kInt, map[uint32]string{201: "Residual Session Context Removed",
		401: "Unsupported Attribute", 404: "Invalid Request", 503: "Session Context Not Found", 506: "Resources Unavailable"}},
}

// VSA por (vendor, tipo): Cisco (9) y Microsoft (311, RFC 2548).
var vsaDict = map[[2]uint32]def{
	{9, 1}: {"Cisco-AVPair", kText, nil}, {9, 250}: {"Cisco-Account-Info", kText, nil},
	{311, 2}: {"MS-CHAP-Error", kText, nil}, {311, 7}: {"MS-MPPE-Encryption-Policy", kInt, nil},
	{311, 8}: {"MS-MPPE-Encryption-Types", kInt, nil}, {311, 11}: {"MS-CHAP-Challenge", kOctets, nil},
	{311, 16}: {"MS-MPPE-Send-Key", kSecret, nil}, {311, 17}: {"MS-MPPE-Recv-Key", kSecret, nil},
	{311, 25}: {"MS-CHAP2-Response", kSecret, nil}, {311, 26}: {"MS-CHAP2-Success", kTaggedText, nil},
}

// Decoded es un atributo legible. Los valores secretos se reemplazan por su tamaño.
type Decoded struct {
	Name  string
	Value string
}

func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if !unicode.IsPrint(r) && r != '\t' {
			return false
		}
	}
	return true
}

func render(d def, v []byte) string {
	switch d.kind {
	case kText:
		if printable(v) {
			return string(v)
		}
		return "0x" + hex.EncodeToString(v)
	case kInt:
		if len(v) != 4 {
			return "0x" + hex.EncodeToString(v) + " (longitud inválida)"
		}
		n := binary.BigEndian.Uint32(v)
		if s, ok := d.enums[n]; ok {
			return fmt.Sprintf("%s (%d)", s, n)
		}
		return strconv.FormatUint(uint64(n), 10)
	case kIP:
		if a, ok := netip.AddrFromSlice(v); ok {
			return a.String()
		}
		return "0x" + hex.EncodeToString(v)
	case kTaggedInt:
		if len(v) != 4 {
			return "0x" + hex.EncodeToString(v) + " (longitud inválida)"
		}
		n := uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
		s := strconv.FormatUint(uint64(n), 10)
		if e, ok := d.enums[n]; ok {
			s = fmt.Sprintf("%s (%d)", e, n)
		}
		if v[0] != 0 {
			s += fmt.Sprintf(" [etiqueta %d]", v[0])
		}
		return s
	case kTaggedText:
		if len(v) > 0 && v[0] <= 0x1f { // RFC 2868 §3.6: etiqueta solo si es 0x01–0x1F
			return render(def{kind: kText}, v[1:]) + fmt.Sprintf(" [etiqueta %d]", v[0])
		}
		return render(def{kind: kText}, v)
	case kSecret:
		return fmt.Sprintf("(%d bytes, no se muestra)", len(v))
	}
	if printable(v) && len(v) > 0 {
		return string(v)
	}
	return "0x" + hex.EncodeToString(v)
}

// describe convierte un atributo en una o varias líneas legibles; nunca entra en pánico.
func describe(a Attr) []Decoded {
	if a.Type != AttrVendorSpecific {
		d, ok := dict[a.Type]
		if !ok {
			d = def{name: fmt.Sprintf("Atributo-%d", a.Type), kind: kOctets}
		}
		return []Decoded{{d.name, render(d, a.Value)}}
	}
	if len(a.Value) < 4 {
		return []Decoded{{"Vendor-Specific", "0x" + hex.EncodeToString(a.Value) + " (truncado)"}}
	}
	vendor := binary.BigEndian.Uint32(a.Value)
	var out []Decoded
	rest := a.Value[4:]
	for len(rest) > 0 {
		if len(rest) < 2 || rest[1] < 2 || int(rest[1]) > len(rest) {
			return append(out, Decoded{fmt.Sprintf("VSA-%d", vendor), "0x" + hex.EncodeToString(rest) + " (truncado)"})
		}
		t, v := rest[0], rest[2:rest[1]]
		rest = rest[rest[1]:]
		d, ok := vsaDict[[2]uint32{vendor, uint32(t)}]
		if !ok {
			d = def{name: fmt.Sprintf("VSA-%d-%d", vendor, t), kind: kOctets}
		}
		out = append(out, Decoded{d.name, render(d, v)})
	}
	return out
}

// parseEnum acepta el nombre (sin distinguir mayúsculas ni guiones) o el número.
func parseEnum(s string, m map[uint32]string) (uint32, error) {
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return uint32(n), nil
	}
	for n, name := range m {
		if norm(name) == norm(s) {
			return n, nil
		}
	}
	return 0, fmt.Errorf("valor %q desconocido", s)
}

func norm(s string) string {
	b := make([]byte, 0, len(s))
	for _, r := range []byte(s) {
		if r == '-' || r == '_' || r == ' ' || r == '.' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b = append(b, r)
	}
	return string(b)
}
