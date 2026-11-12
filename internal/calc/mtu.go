package calc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

type MTULayer struct {
	Layer     string    `json:"layer"`
	Detail    string    `json:"detail"`
	Bytes     int       `json:"bytes"`
	Remaining int       `json:"remaining"`
	dkey      string    // calc.val.mtu.* del detalle
	dargs     i18n.Args //
}

type MTUResult struct {
	Physical        int        `json:"physical"`
	InnerIPv6       bool       `json:"innerIpv6"`
	Layers          []MTULayer `json:"layers"`
	Overhead        int        `json:"overhead"`
	Effective       int        `json:"effective"`
	IPMTU           int        `json:"ipMtu"`
	MSS             int        `json:"mss"`
	PhysicalFor1500 int        `json:"physicalFor1500,omitempty"`
	Notes           []string   `json:"notes,omitempty"`
	notes           []Note
}

// Cifrados ESP: IV, bloque al que se alinea lo cifrado e ICV propio (AEAD).
var espCiphers = map[string]struct{ iv, block, icv int }{
	"aes-cbc": {16, 16, 0}, "aes-gcm": {8, 4, 16}, "3des": {8, 8, 0}, "des": {8, 8, 0},
}

// ICV de las autenticaciones HMAC truncadas (RFC 2404, 4868, 2403).
var espAuths = map[string]int{"md5": 12, "sha1": 12, "sha256": 16, "sha384": 24, "sha512": 32}

// Capas simples: bytes y detalle. outerIP marca las que agregan su propia cabecera IPv4.
var simpleLayers = map[string]struct {
	bytes   int
	detail  string // sufijo de calc.val.mtu.*
	outerIP bool
}{
	"gre":     {24, "gre", true},
	"gre-key": {28, "gre_key", true},
	"nat-t":   {8, "nat_t", false},
	"vxlan":   {50, "vxlan", true},
	"lisp":    {36, "lisp", true},
	"pppoe":   {8, "pppoe", false},
}

const mtuLayersHelp = "gre, gre-key, esp-tunnel:CIFRADO[:AUT], esp-transport:CIFRADO[:AUT], getvpn:CIFRADO[:AUT][:tbar], nat-t, vxlan, mpls[:N], dot1q, qinq, pppoe, lisp (CIFRADO: aes-cbc, aes-gcm, 3des, des; AUT: sha1, sha256, sha384, sha512, md5)"

// MTU recorre la pila de afuera hacia adentro restando cada encabezado sobre la MTU
// IP física; ESP se resuelve exacto: lo cifrado (carga + 2 de cola) se alinea al bloque.
func MTU(phys int, stack []string, inner6 bool) (MTUResult, error) {
	if phys < 68 || phys > 65535 {
		return MTUResult{}, fmt.Errorf("MTU física %d fuera de rango (68–65535)", phys)
	}
	if len(stack) == 0 {
		return MTUResult{}, errors.New("indica al menos una capa: " + mtuLayersHelp)
	}
	r, err := walk(phys, stack)
	if err != nil {
		return MTUResult{}, err
	}
	hdr, minMTU := 40, 68
	if inner6 {
		hdr, minMTU = 60, 1280
	}
	if r.Effective < 68 || r.Effective-hdr < 1 {
		return MTUResult{}, fmt.Errorf("la pila deja %d bytes: no cabe en una MTU física de %d", r.Effective, phys)
	}
	r.InnerIPv6, r.IPMTU, r.MSS = inner6, r.Effective, r.Effective-hdr
	if r.Effective < minMTU {
		addNote(&r.Notes, &r.notes, "calc.note.mtu_ipv6_min", "effective", r.Effective)
	}
	if r.Effective < 1500 {
		for p := phys + 1; p <= 65535; p++ {
			if w, err := walk(p, stack); err == nil && w.Effective >= 1500 {
				r.PhysicalFor1500 = p
				break
			}
		}
	}
	return r, nil
}

func walk(phys int, stack []string) (MTUResult, error) {
	r := MTUResult{Physical: phys}
	avail, inL2, lifted, ipsec, vxlan := phys, false, false, false, false
	liftIdx := -1 // capa ESP de transporte cuya IP protegida quedó por fuera
	add := func(name, key string, args i18n.Args, bytes int) {
		avail -= bytes
		key = "calc.val.mtu." + key
		r.Layers = append(r.Layers, MTULayer{Layer: name, Detail: i18n.Msg(i18n.Es, key, args), Bytes: bytes, Remaining: avail, dkey: key, dargs: args})
	}
	for i, raw := range stack {
		f := strings.Split(strings.ToLower(strings.TrimSpace(raw)), ":")
		name := f[0]
		// NAT-T es el UDP 4500 que envuelve al ESP: solo vale justo por fuera de él.
		if name == "nat-t" && (i+1 >= len(stack) || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(stack[i+1])), "esp-")) {
			return r, errors.New("nat-t va inmediatamente antes (por fuera) de una capa esp-tunnel o esp-transport")
		}
		if s, ok := simpleLayers[name]; ok && len(f) == 1 && (!lifted || s.outerIP) {
			b, ip := s.bytes, "calc.val.mtu.ip_outer"
			if s.outerIP && lifted { // su IP quedó delante del ESP de transporte
				b, ip, lifted = b-20, "calc.val.mtu.ip_counted", false
			}
			add(name, s.detail, i18n.A("ip", ip), b)
			inL2 = inL2 || name == "vxlan"
			vxlan = vxlan || name == "vxlan"
			continue
		}
		if lifted {
			return r, fmt.Errorf("ESP de transporte protege un paquete IP: después solo van gre, gre-key, vxlan o lisp, no %q", raw)
		}
		switch name {
		case "mpls":
			n := 1
			if len(f) == 2 {
				var err error
				if n, err = strconv.Atoi(f[1]); err != nil || n < 1 || n > 16 {
					return r, fmt.Errorf("etiquetas MPLS %q inválidas (1–16)", f[1])
				}
			} else if len(f) > 2 {
				return r, fmt.Errorf("capa %q inválida", raw)
			}
			add(name, "mpls", i18n.A("n", n), 4*n)
		case "dot1q", "qinq":
			b := map[string]int{"dot1q": 4, "qinq": 8}[name]
			if inL2 {
				add(name, "tag_inner", i18n.A("bytes", b), b)
			} else {
				add(name, "tag_outer", nil, 0)
				addNote(&r.Notes, &r.notes, "calc.note.mtu_outer_tag", "layer", name, "frame", phys+18+b)
			}
		case "esp-tunnel", "esp-transport", "getvpn":
			tbar := name == "getvpn" && len(f) > 2 && f[len(f)-1] == "tbar"
			if tbar {
				f = f[:len(f)-1]
			}
			c, ok := espCiphers[get(f, 1)]
			if !ok {
				return r, fmt.Errorf("cifrado ESP %q desconocido en %q (aes-cbc, aes-gcm, 3des, des)", get(f, 1), raw)
			}
			icv, auth := c.icv, get(f, 2)
			switch {
			case c.icv > 0 && auth != "":
				return r, fmt.Errorf("%s ya autentica: quita %q", get(f, 1), auth)
			case c.icv == 0:
				if icv, ok = espAuths[auth]; !ok {
					return r, fmt.Errorf("autenticación ESP %q desconocida en %q (sha1, sha256, sha384, sha512, md5)", auth, raw)
				}
			}
			if len(f) > 3 {
				return r, fmt.Errorf("capa %q inválida", raw)
			}
			ipLabel := "calc.val.mtu.ip_outer"
			switch name {
			case "esp-transport":
				ipLabel, lifted, liftIdx = "calc.val.mtu.ip_protected", true, len(r.Layers)
			case "getvpn":
				ipLabel = "calc.val.mtu.ip_getvpn"
			}
			fixed := 20 + 8 + c.iv + icv
			if tbar {
				fixed += 12
			}
			ct := (avail - fixed) / c.block * c.block // lo cifrado: carga + relleno + 2
			if ct < 2 {
				return r, fmt.Errorf("no cabe ESP en %d bytes", avail)
			}
			align := avail - fixed - ct
			tb := ""
			if tbar {
				tb = "calc.val.mtu.tbar"
			}
			add(raw, "esp", i18n.A("ip", ipLabel, "iv", c.iv, "icv", icv, "tbar", tb, "align", align, "block", c.block), avail-(ct-2))
			ipsec = true
		default:
			return r, fmt.Errorf("capa %q desconocida; usa %s", raw, mtuLayersHelp)
		}
	}
	if lifted { // transporte sin nada dentro: el paquete conserva su propia cabecera
		last := &r.Layers[liftIdx]
		last.Bytes -= 20
		avail += 20
		last.Remaining = avail
		last.dargs["ip"] = "calc.val.mtu.ip_own"
		last.Detail = i18n.Msg(i18n.Es, last.dkey, last.dargs)
	}
	r.Effective, r.Overhead = avail, phys-avail
	if ipsec {
		addNote(&r.Notes, &r.notes, "calc.note.mtu_esp_padding")
	}
	if vxlan {
		addNote(&r.Notes, &r.notes, "calc.note.mtu_vxlan")
	}
	return r, nil
}

func get(f []string, i int) string {
	if i < len(f) {
		return f[i]
	}
	return ""
}

func (r MTUResult) Report() Report {
	t := titled("calc.title.mtu_breakdown", i18n.A("physical", r.Physical), "calc.col.layer", "calc.col.detail", "calc.col.bytes", "calc.col.remaining")
	for _, l := range r.Layers {
		t.add("", nil, l.Layer, val{key: l.dkey, args: l.dargs}, strconv.Itoa(l.Bytes), strconv.Itoa(l.Remaining))
	}
	inner := "IPv4 + TCP 40"
	if r.InnerIPv6 {
		inner = "IPv6 + TCP 60"
	}
	need := ""
	if r.PhysicalFor1500 > 0 {
		need = strconv.Itoa(r.PhysicalFor1500)
	}
	res := kv("calc.title.result", nil, "calc.row.overhead", strconv.Itoa(r.Overhead), "calc.row.effective_mtu", strconv.Itoa(r.Effective),
		"calc.row.ip_mtu", strconv.Itoa(r.IPMTU), lbl{"calc.row.adjust_mss", i18n.A("inner", inner)}, strconv.Itoa(r.MSS), "calc.row.physical_1500", need)
	return Report{Tables: []Table{t, res}, Notes: r.Notes, NoteItems: r.notes}
}
