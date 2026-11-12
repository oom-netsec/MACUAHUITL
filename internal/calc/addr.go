package calc

import (
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ---- utilidades de direcciones ----

// lastAddr es la última dirección del prefijo (todos los bits de host en 1).
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// mask4 son n unos seguidos de ceros (en Go, desplazar 32 da 0: /0 sale bien).
func mask4(n int) uint32 { return ^uint32(0) << (32 - n) }

func v4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func fromV4(u uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)})
}

// contiguousLen devuelve la longitud de una máscara IPv4 contigua (unos y luego ceros).
func contiguousLen(m uint32) (int, bool) {
	n := bits.LeadingZeros32(^m)
	return n, n == 32 || m<<n == 0
}

func pow2(n int) *big.Int { return new(big.Int).Lsh(big.NewInt(1), uint(n)) }

func size(p netip.Prefix) *big.Int { return pow2(p.Addr().BitLen() - p.Bits()) }

// parsePrefix acepta "a/n", "a/máscara" y "a máscara"; devuelve el prefijo
// normalizado y la dirección tal como la escribió el ingeniero.
func parsePrefix(s string) (netip.Prefix, netip.Addr, error) {
	s = strings.TrimSpace(s)
	addr, rest, ok := strings.Cut(s, "/")
	if !ok {
		f := strings.Fields(s)
		if len(f) != 2 {
			return netip.Prefix{}, netip.Addr{}, fmt.Errorf("%q: indica el prefijo (10.0.0.0/24 o 10.0.0.0 255.255.255.0)", s)
		}
		addr, rest = f[0], f[1]
	}
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("dirección %q inválida", addr)
	}
	a = a.WithZone("")
	n, err := strconv.Atoi(rest)
	if err != nil {
		m, merr := netip.ParseAddr(rest)
		if merr != nil || !a.Is4() || !m.Is4() {
			return netip.Prefix{}, netip.Addr{}, fmt.Errorf("prefijo o máscara %q inválido", rest)
		}
		var ok bool
		if n, ok = contiguousLen(v4(m)); !ok {
			return netip.Prefix{}, netip.Addr{}, fmt.Errorf("máscara %s no contigua", rest)
		}
	}
	if n < 0 || n > a.BitLen() {
		return netip.Prefix{}, netip.Addr{}, fmt.Errorf("longitud /%s fuera de rango", rest)
	}
	return netip.PrefixFrom(a, n).Masked(), a, nil
}

// rangeToPrefixes cubre exactamente [a, b] con la menor cantidad de prefijos.
func rangeToPrefixes(a, b netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for {
		var p netip.Prefix
		for l := 0; l <= a.BitLen(); l++ {
			p = netip.PrefixFrom(a, l).Masked()
			if p.Addr() == a && lastAddr(p).Compare(b) <= 0 {
				break
			}
		}
		out = append(out, p)
		e := lastAddr(p)
		if e == b {
			return out
		}
		a = e.Next()
	}
}

func commonBits(a, b netip.Addr) int {
	x, y := a.AsSlice(), b.AsSlice()
	for i := range x {
		if d := x[i] ^ y[i]; d != 0 {
			return i*8 + bits.LeadingZeros8(d)
		}
	}
	return len(x) * 8
}

type special struct {
	p    netip.Prefix
	name string
}

func specials(pairs ...string) []special {
	out := make([]special, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, special{netip.MustParsePrefix(pairs[i]), pairs[i+1]})
	}
	return out
}

// Gana el primer bloque que contiene la dirección: los específicos van antes.
var specials4 = specials(
	"0.0.0.0/8", `"esta red" (RFC 791)`, "10.0.0.0/8", "privada (RFC 1918)", "100.64.0.0/10", "CGNAT (RFC 6598)",
	"127.0.0.0/8", "loopback (RFC 1122)", "169.254.0.0/16", "enlace local (RFC 3927)", "172.16.0.0/12", "privada (RFC 1918)",
	"192.0.0.0/24", "asignaciones de protocolo IETF (RFC 6890)", "192.0.2.0/24", "documentación (RFC 5737)",
	"192.88.99.0/24", "relé 6to4 obsoleto (RFC 7526)", "192.168.0.0/16", "privada (RFC 1918)",
	"198.18.0.0/15", "pruebas de rendimiento (RFC 2544)", "198.51.100.0/24", "documentación (RFC 5737)",
	"203.0.113.0/24", "documentación (RFC 5737)", "224.0.0.0/24", "multicast local (RFC 5771)",
	"232.0.0.0/8", "multicast SSM (RFC 4607)", "239.0.0.0/8", "multicast administrativo (RFC 2365)",
	"224.0.0.0/4", "multicast (RFC 5771)", "255.255.255.255/32", "broadcast limitado (RFC 919)", "240.0.0.0/4", "reservada (RFC 1112)",
)

var specials6 = specials(
	"::/128", "no especificada", "::1/128", "loopback", "::ffff:0:0/96", "IPv4 mapeada (RFC 4291)",
	"64:ff9b::/96", "NAT64 (RFC 6052)", "100::/64", "descarte (RFC 6666)", "2001::/32", "Teredo (RFC 4380)",
	"2001:db8::/32", "documentación (RFC 3849)", "2002::/16", "6to4 (RFC 3056)", "2000::/3", "unicast global (RFC 4291)",
	"fc00::/7", "local única ULA (RFC 4193)", "fe80::/10", "enlace local (RFC 4291)", "fec0::/10", "site-local obsoleta (RFC 3879)",
	"ff02::1:ff00:0/104", "multicast nodo solicitado (RFC 4291)", "ff00::/8", "multicast",
)

var mcastScope = map[byte]string{1: "interfaz", 2: "enlace", 3: "red", 4: "administración", 5: "sitio", 8: "organización", 0xe: "global"}

func kind(a netip.Addr) string { return prefixKind(netip.PrefixFrom(a, a.BitLen())) }

// prefixKind etiqueta el prefijo completo: un bloque especial solo cuenta si lo contiene
// entero; si el prefijo cubre bloques especiales sin caber en uno, es mixto.
func prefixKind(p netip.Prefix) string {
	if p.Bits() == 0 {
		return "cualquiera (ruta por defecto)"
	}
	a := p.Addr()
	list := specials4
	if a.Is6() {
		list = specials6
	}
	mixed := false
	for _, s := range list {
		if p.Contains(s.p.Addr()) && s.p.Bits() > p.Bits() {
			mixed = true
		}
		if s.p.Bits() <= p.Bits() && s.p.Contains(a) {
			if s.name == "multicast" {
				if sc, ok := mcastScope[a.As16()[1]&0x0f]; ok {
					return "multicast, alcance " + sc
				}
			}
			return s.name
		}
	}
	if mixed {
		return "mixta (cubre bloques de distinto tipo)"
	}
	if a.Is6() {
		return "sin asignar (fuera de 2000::/3)"
	}
	return "pública"
}

func class4(a netip.Addr) string {
	switch o := a.As4()[0]; {
	case o < 128:
		return "A"
	case o < 192:
		return "B"
	case o < 224:
		return "C"
	case o < 240:
		return "D"
	}
	return "E"
}

// ---- información de subred ----

type SubnetInfo struct {
	Input       string   `json:"input"`
	Prefix      string   `json:"prefix"`
	PrefixLen   int      `json:"prefixLen"`
	Network     string   `json:"network"`
	Broadcast   string   `json:"broadcast,omitempty"`
	FirstUsable string   `json:"firstUsable"`
	LastUsable  string   `json:"lastUsable"`
	Mask        string   `json:"mask,omitempty"`
	Wildcard    string   `json:"wildcard,omitempty"`
	Total       string   `json:"total"`
	Usable      string   `json:"usable"`
	Kind        string   `json:"kind"`
	Class       string   `json:"class,omitempty"`
	Notes       []string `json:"notes,omitempty"`
	notes       []Note
}

func Subnet(in string) (SubnetInfo, error) {
	p, given, err := parsePrefix(in)
	if err != nil {
		return SubnetInfo{}, err
	}
	n, net, last := p.Bits(), p.Addr(), lastAddr(p)
	s := SubnetInfo{Input: in, Prefix: p.String(), PrefixLen: n, Network: net.String(), Total: size(p).String(), Kind: prefixKind(p)}
	if given != net {
		addNote(&s.Notes, &s.notes, "calc.note.host_in_subnet", "addr", given, "prefix", p)
	}
	if net.Is6() {
		s.FirstUsable, s.LastUsable, s.Usable = net.String(), last.String(), s.Total
		switch {
		case n == 127:
			addNote(&s.Notes, &s.notes, "calc.note.p2p_v6")
		case n < 127:
			addNote(&s.Notes, &s.notes, "calc.note.anycast_v6")
		}
		return s, nil
	}
	m := mask4(n)
	s.Mask, s.Wildcard, s.Class = fromV4(m).String(), fromV4(^m).String(), class4(net)
	switch n {
	case 32:
		s.FirstUsable, s.LastUsable, s.Usable = net.String(), net.String(), "1"
		addNote(&s.Notes, &s.notes, "calc.note.single_host")
	case 31:
		s.FirstUsable, s.LastUsable, s.Usable = net.String(), last.String(), "2"
		addNote(&s.Notes, &s.notes, "calc.note.p2p_v4")
	default:
		s.Broadcast, s.FirstUsable, s.LastUsable = last.String(), net.Next().String(), last.Prev().String()
		s.Usable = new(big.Int).Sub(size(p), big.NewInt(2)).String()
	}
	return s, nil
}

func (s SubnetInfo) Report() Report {
	return Report{Tables: []Table{kv("calc.title.subnet", i18n.A("prefix", s.Prefix),
		"calc.row.network", s.Network, "calc.row.broadcast", s.Broadcast, "calc.row.first_usable", s.FirstUsable, "calc.row.last_usable", s.LastUsable,
		"calc.row.addresses", s.Total, "calc.row.usable_hosts", s.Usable, "calc.row.prefix", "/"+strconv.Itoa(s.PrefixLen), "calc.row.mask", s.Mask,
		"calc.row.wildcard", s.Wildcard, "calc.row.class", s.Class, "calc.row.kind", s.Kind)}, Notes: s.Notes, NoteItems: s.notes}
}

// ---- VLSM ----

type Need struct {
	Name  string `json:"name"`
	Hosts uint64 `json:"hosts"`
}

type Allocation struct {
	Name      string `json:"name"`
	Hosts     uint64 `json:"hosts"`
	Prefix    string `json:"prefix"`
	Mask      string `json:"mask,omitempty"`
	First     string `json:"first"`
	Last      string `json:"last"`
	Broadcast string `json:"broadcast,omitempty"`
	Capacity  string `json:"capacity"`
	Waste     string `json:"waste"`
}

type VLSMResult struct {
	Parent      string       `json:"parent"`
	Allocations []Allocation `json:"allocations"`
	Unplaced    []string     `json:"unplaced"`
	Free        []string     `json:"free"`
}

// hostBits es el bloque mínimo para n hosts; en IPv4 resta red y broadcast (así 1 o 2 hosts dan /30).
func hostBits(n uint64, v6 bool) int {
	if v6 {
		return bits.Len64(n - 1)
	}
	if n >= 1<<32 {
		return 33 // no cabe en IPv4
	}
	return bits.Len64(n + 1)
}

// VLSM reparte la red de mayor a menor necesidad, alineado y sin traslapes. Lo que
// no cabe se reporta y se sigue con lo más chico, que aún puede acomodarse.
func VLSM(parent string, needs []Need) (VLSMResult, error) {
	p, _, err := parsePrefix(parent)
	if err != nil {
		return VLSMResult{}, err
	}
	if len(needs) == 0 {
		return VLSMResult{}, errors.New("indica al menos una necesidad de hosts")
	}
	sorted := slices.Clone(needs)
	for i, n := range sorted {
		if n.Hosts == 0 {
			return VLSMResult{}, fmt.Errorf("%q pide 0 hosts", n.Name)
		}
		if n.Name == "" {
			sorted[i].Name = fmt.Sprintf("red %d", i+1)
		}
	}
	slices.SortStableFunc(sorted, func(a, b Need) int { return -cmpU(a.Hosts, b.Hosts) })
	v6, bitLen, end := p.Addr().Is6(), p.Addr().BitLen(), lastAddr(p)
	r := VLSMResult{Parent: p.String(), Allocations: []Allocation{}, Unplaced: []string{}, Free: []string{}}
	cur := p.Addr()
	for _, n := range sorted {
		h := hostBits(n.Hosts, v6)
		if h > bitLen-p.Bits() {
			r.Unplaced = append(r.Unplaced, fmt.Sprintf("%s (%d hosts)", n.Name, n.Hosts))
			continue
		}
		// De mayor a menor, cada bloque empieza alineado: no hay huecos que rellenar.
		b := netip.PrefixFrom(cur, bitLen-h)
		if !b.Addr().IsValid() || !p.Contains(b.Addr()) || lastAddr(b).Compare(end) > 0 {
			r.Unplaced = append(r.Unplaced, fmt.Sprintf("%s (%d hosts)", n.Name, n.Hosts))
			continue
		}
		s, _ := Subnet(b.String())
		capacity, _ := new(big.Int).SetString(s.Usable, 10)
		r.Allocations = append(r.Allocations, Allocation{Name: n.Name, Hosts: n.Hosts, Prefix: b.String(), Mask: s.Mask, First: s.FirstUsable,
			Last: s.LastUsable, Broadcast: s.Broadcast, Capacity: s.Usable, Waste: capacity.Sub(capacity, new(big.Int).SetUint64(n.Hosts)).String()})
		cur = lastAddr(b).Next()
	}
	if cur.IsValid() && p.Contains(cur) {
		for _, f := range rangeToPrefixes(cur, end) {
			r.Free = append(r.Free, f.String())
		}
	}
	return r, nil
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (v VLSMResult) Report() Report {
	t := titled("calc.title.vlsm", i18n.A("parent", v.Parent), "calc.col.name", "calc.col.hosts", "calc.col.prefix", "calc.col.mask", "calc.col.first", "calc.col.last", "calc.col.broadcast", "calc.col.capacity", "calc.col.waste")
	for _, a := range v.Allocations {
		t.add("", nil, a.Name, strconv.FormatUint(a.Hosts, 10), a.Prefix, a.Mask, a.First, a.Last, a.Broadcast, a.Capacity, a.Waste)
	}
	r := Report{Tables: []Table{t}}
	if len(v.Unplaced) > 0 {
		addNote(&r.Notes, &r.NoteItems, "calc.note.vlsm_unplaced", "names", strings.Join(v.Unplaced, ", "))
	}
	if len(v.Free) > 0 {
		addNote(&r.Notes, &r.NoteItems, "calc.note.vlsm_free", "free", strings.Join(v.Free, " "))
	}
	return r
}

// ---- sumarización ----

type Summary struct {
	Inputs  []string `json:"inputs"`
	Exact   []string `json:"exact"`
	Single  string   `json:"single"`
	Covered string   `json:"covered"`
	Extra   string   `json:"extra"`
}

// Summarize da el conjunto mínimo de prefijos que cubre exactamente lo mismo que la
// lista, y el único prefijo más chico que la contiene (con las direcciones ajenas que arrastra).
func Summarize(in []string) (Summary, error) {
	type rng struct{ a, b netip.Addr }
	var rs []rng
	for _, s := range in {
		if strings.TrimSpace(s) == "" {
			continue
		}
		p, _, err := parsePrefix(s)
		if err != nil {
			return Summary{}, err
		}
		if len(rs) > 0 && rs[0].a.Is4() != p.Addr().Is4() {
			return Summary{}, errors.New("no se pueden mezclar IPv4 e IPv6")
		}
		rs = append(rs, rng{p.Addr(), lastAddr(p)})
	}
	if len(rs) == 0 {
		return Summary{}, errors.New("indica al menos un prefijo")
	}
	slices.SortFunc(rs, func(x, y rng) int { return x.a.Compare(y.a) })
	merged := []rng{rs[0]}
	for _, r := range rs[1:] {
		m := &merged[len(merged)-1]
		if n := m.b.Next(); !n.IsValid() || r.a.Compare(n) <= 0 { // traslapa o es contiguo
			if r.b.Compare(m.b) > 0 {
				m.b = r.b
			}
			continue
		}
		merged = append(merged, r)
	}
	s := Summary{Inputs: in}
	covered := new(big.Int)
	hi := merged[0].b
	for _, m := range merged {
		for _, p := range rangeToPrefixes(m.a, m.b) {
			s.Exact = append(s.Exact, p.String())
			covered.Add(covered, size(p))
		}
		if m.b.Compare(hi) > 0 {
			hi = m.b
		}
	}
	single := netip.PrefixFrom(merged[0].a, commonBits(merged[0].a, hi)).Masked()
	s.Single, s.Covered, s.Extra = single.String(), covered.String(), new(big.Int).Sub(size(single), covered).String()
	return s, nil
}

func (s Summary) Report() Report {
	t := titled("calc.title.summary", nil, "calc.col.type", "calc.col.prefixes")
	t.add("calc.row.exact", nil, "", strings.Join(s.Exact, " "))
	t.add("calc.row.single", nil, "", s.Single)
	r := Report{Tables: []Table{t}}
	addNote(&r.Notes, &r.NoteItems, "calc.note.summary_covered", "covered", s.Covered)
	if s.Extra != "0" {
		addNote(&r.Notes, &r.NoteItems, "calc.note.summary_extra", "single", s.Single, "extra", s.Extra)
	}
	return r
}

// ---- máscaras y wildcards ----

type OctetMatch struct {
	Value    int    `json:"value"`
	Wildcard int    `json:"wildcard"`
	Binary   string `json:"binary"`
	Values   string `json:"values"`
}

type WildcardInfo struct {
	Address     string       `json:"address,omitempty"`
	Base        string       `json:"base,omitempty"`
	PrefixLen   string       `json:"prefixLen,omitempty"`
	Mask        string       `json:"mask,omitempty"`
	Wildcard    string       `json:"wildcard"`
	Contiguous  bool         `json:"contiguous"`
	Matches     string       `json:"matches"`
	First       string       `json:"first,omitempty"`
	Last        string       `json:"last,omitempty"`
	PrefixCount string       `json:"prefixCount,omitempty"`
	Prefixes    []string     `json:"prefixes,omitempty"`
	Octets      []OctetMatch `json:"octets,omitempty"`
	Notes       []string     `json:"notes,omitempty"`
	notes       []Note
}

const maxListed = 16

// Wildcard sin dirección convierte entre prefijo, máscara y wildcard. Con dirección
// muestra qué cubre una entrada de ACL, aunque la wildcard no sea contigua.
func Wildcard(addr, value string) (WildcardInfo, error) {
	value = strings.TrimSpace(value)
	if strings.TrimSpace(addr) == "" {
		return convertMask(value)
	}
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil || !a.Is4() {
		return WildcardInfo{}, fmt.Errorf("dirección IPv4 %q inválida (las ACL IPv6 usan prefijos, no wildcards)", addr)
	}
	m, err := netip.ParseAddr(value)
	if err != nil || !m.Is4() {
		return WildcardInfo{}, fmt.Errorf("wildcard %q inválida", value)
	}
	w, base := v4(m), v4(a)&^v4(m)
	t := bits.TrailingZeros32(^w) // bits bajos libres contiguos
	high := w
	if t < 32 {
		high &^= 1<<t - 1
	} else {
		high = 0
	}
	plen := 32 - t
	info := WildcardInfo{Address: a.String(), Base: fromV4(base).String(), Wildcard: m.String(), Contiguous: w&(w+1) == 0,
		Matches: strconv.FormatUint(1<<bits.OnesCount32(w), 10), First: fromV4(base).String(), Last: fromV4(base | w).String(),
		PrefixCount: strconv.FormatUint(1<<bits.OnesCount32(high), 10)}
	if info.Contiguous {
		info.PrefixLen, info.Mask = strconv.Itoa(plen), fromV4(^w).String()
	}
	if base != v4(a) {
		addNote(&info.Notes, &info.notes, "calc.note.wildcard_host_bits", "addr", a, "base", info.Base)
	}
	for sub := uint32(0); len(info.Prefixes) < maxListed; {
		info.Prefixes = append(info.Prefixes, fmt.Sprintf("%s/%d", fromV4(base|sub), plen))
		if sub = (sub - high) & high; sub == 0 { // siguiente subconjunto de bits libres, en orden
			break
		}
	}
	for i := 0; i < 4; i++ {
		v, wo := int(base>>(24-8*i))&0xff, int(w>>(24-8*i))&0xff
		info.Octets = append(info.Octets, OctetMatch{Value: v, Wildcard: wo, Binary: fmt.Sprintf("%08b", wo), Values: octetValues(v, wo)})
	}
	if !info.Contiguous {
		addNote(&info.Notes, &info.notes, "calc.note.wildcard_noncontiguous")
	}
	return info, nil
}

func octetValues(v, w int) string {
	switch {
	case w == 0:
		return "solo " + strconv.Itoa(v)
	case w&(w+1) == 0:
		return fmt.Sprintf("de %d a %d", v, v|w)
	case w == 0xfe && v == 0:
		return "pares de 0 a 254"
	case w == 0xfe:
		return "impares de 1 a 255"
	}
	var vals []string
	for x := 0; x < 256 && len(vals) < 8; x++ {
		if x&^w == v {
			vals = append(vals, strconv.Itoa(x))
		}
	}
	return fmt.Sprintf("%s… (%d valores)", strings.Join(vals, ", "), 1<<bits.OnesCount8(uint8(w)))
}

func convertMask(v string) (WildcardInfo, error) {
	n, err := strconv.Atoi(strings.TrimPrefix(v, "/"))
	if err != nil {
		m, perr := netip.ParseAddr(v)
		if perr != nil || !m.Is4() {
			return WildcardInfo{}, fmt.Errorf("%q no es prefijo, máscara ni wildcard IPv4", v)
		}
		var ok bool
		if n, ok = contiguousLen(v4(m)); !ok { // ¿máscara? si no, ¿wildcard?
			if n, ok = contiguousLen(^v4(m)); !ok {
				return WildcardInfo{}, fmt.Errorf("%s no es contigua: indica la dirección de la ACL para ver qué cubre", v)
			}
		}
	}
	if n < 0 || n > 32 {
		return WildcardInfo{}, fmt.Errorf("prefijo /%d fuera de rango", n)
	}
	m := mask4(n)
	return WildcardInfo{PrefixLen: strconv.Itoa(n), Mask: fromV4(m).String(), Wildcard: fromV4(^m).String(), Contiguous: true,
		Matches: strconv.FormatUint(1<<(32-n), 10)}, nil
}

func (w WildcardInfo) Report() Report {
	r := Report{Notes: w.Notes, NoteItems: w.notes}
	if w.Address == "" {
		r.Tables = []Table{kv("calc.title.conversion", nil, "calc.row.prefix", "/"+w.PrefixLen, "calc.row.mask", w.Mask, "calc.row.wildcard", w.Wildcard, "calc.row.addresses", w.Matches)}
		return r
	}
	pl := ""
	if w.PrefixLen != "" {
		pl = w.Base + "/" + w.PrefixLen
	}
	r.Tables = append(r.Tables, kv("calc.title.acl", i18n.A("base", w.Base, "wildcard", w.Wildcard), "calc.row.matches", w.Matches, "calc.row.first", w.First, "calc.row.last", w.Last,
		"calc.row.equals", pl, "calc.row.prefixes_needed", w.PrefixCount))
	ot := titled("calc.title.octets", nil, "calc.col.octet", "calc.col.value", "calc.col.wildcard", "calc.col.binary", "calc.col.matching")
	for i, o := range w.Octets {
		ot.add("", nil, strconv.Itoa(i+1), strconv.Itoa(o.Value), strconv.Itoa(o.Wildcard), o.Binary, o.Values)
	}
	pt := titled("calc.title.covered", nil, "calc.col.prefix")
	if w.PrefixCount != strconv.Itoa(len(w.Prefixes)) {
		pt = titled("calc.title.covered_partial", i18n.A("shown", len(w.Prefixes), "total", w.PrefixCount), "calc.col.prefix")
	}
	for _, p := range w.Prefixes {
		pt.add("", nil, p)
	}
	r.Tables = append(r.Tables, ot, pt)
	return r
}

// ---- IPv6 ----

type IPv6Info struct {
	Compressed    string `json:"compressed"`
	Expanded      string `json:"expanded"`
	Prefix        string `json:"prefix,omitempty"`
	Kind          string `json:"kind"`
	SolicitedNode string `json:"solicitedNode,omitempty"`
	InterfaceID   string `json:"interfaceId,omitempty"`
	EUI64         string `json:"eui64,omitempty"`
	MAC           string `json:"mac,omitempty"`
	ReverseDNS    string `json:"reverseDns"`
}

func parseMAC(s string) ([6]byte, error) {
	var m [6]byte
	h := strings.NewReplacer(":", "", "-", "", ".", "").Replace(strings.TrimSpace(s))
	if len(h) != 12 {
		return m, fmt.Errorf("MAC %q inválida", s)
	}
	for i := range m {
		b, err := strconv.ParseUint(h[2*i:2*i+2], 16, 8)
		if err != nil {
			return m, fmt.Errorf("MAC %q inválida", s)
		}
		m[i] = byte(b)
	}
	return m, nil
}

// IPv6 abrevia, expande y clasifica una dirección; con MAC arma la EUI-64 sobre el
// /64 indicado (o fe80::/64 si no hay prefijo).
func IPv6(addr, mac string) (IPv6Info, error) {
	addr, mac = strings.TrimSpace(addr), strings.TrimSpace(mac)
	if addr == "" && mac == "" {
		return IPv6Info{}, errors.New("indica una dirección IPv6 o una MAC")
	}
	var a netip.Addr
	var prefix string
	if mac != "" {
		m, err := parseMAC(mac)
		if err != nil {
			return IPv6Info{}, err
		}
		p := netip.MustParsePrefix("fe80::/64")
		if addr != "" {
			if p, _, err = parsePrefix(addr); err != nil || !p.Addr().Is6() || p.Bits() != 64 {
				return IPv6Info{}, fmt.Errorf("EUI-64 requiere un prefijo IPv6 /64 (recibí %q)", addr)
			}
		}
		b := p.Addr().As16()
		copy(b[8:], []byte{m[0] ^ 0x02, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]})
		a, prefix = netip.AddrFrom16(b), p.String()
	} else {
		s, _, _ := strings.Cut(addr, "/")
		var err error
		if a, err = netip.ParseAddr(s); err != nil || !a.Is6() {
			return IPv6Info{}, fmt.Errorf("dirección IPv6 %q inválida", addr)
		}
		if strings.Contains(addr, "/") {
			p, _, err := parsePrefix(addr)
			if err != nil {
				return IPv6Info{}, err
			}
			prefix = p.String()
		}
	}
	a = a.WithZone("")
	b := a.As16()
	r := IPv6Info{Compressed: a.String(), Expanded: a.StringExpanded(), Prefix: prefix, Kind: kind(a)}
	if mac != "" {
		r.EUI64 = r.Compressed
	}
	if !a.IsMulticast() && !a.IsUnspecified() {
		r.SolicitedNode = netip.AddrFrom16([16]byte{0: 0xff, 1: 0x02, 11: 1, 12: 0xff, 13: b[13], 14: b[14], 15: b[15]}).String()
		r.InterfaceID = fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x", b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
		if b[11] == 0xff && b[12] == 0xfe {
			r.MAC = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[8]^0x02, b[9], b[10], b[13], b[14], b[15])
		}
	}
	var rev strings.Builder
	for i := 15; i >= 0; i-- {
		fmt.Fprintf(&rev, "%x.%x.", b[i]&0x0f, b[i]>>4)
	}
	r.ReverseDNS = rev.String() + "ip6.arpa"
	return r, nil
}

func (r IPv6Info) Report() Report {
	rep := Report{Tables: []Table{kv("calc.title.ipv6", nil,
		"calc.row.abbreviated", r.Compressed, "calc.row.expanded", r.Expanded, "calc.row.prefix", r.Prefix, "calc.row.kind", r.Kind, "calc.row.eui64", r.EUI64,
		"calc.row.interface_id", r.InterfaceID, "calc.row.mac_eui64", r.MAC, "calc.row.solicited", r.SolicitedNode, "calc.row.ptr", r.ReverseDNS)}}
	if r.MAC != "" && r.EUI64 == "" {
		addNote(&rep.Notes, &rep.NoteItems, "calc.note.ipv6_eui64_mac")
	}
	return rep
}
