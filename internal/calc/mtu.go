package calc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type MTULayer struct {
	Layer     string `json:"layer"`
	Detail    string `json:"detail"`
	Bytes     int    `json:"bytes"`
	Remaining int    `json:"remaining"`
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
	detail  string
	outerIP bool
}{
	"gre":     {24, "IP externa 20 + GRE 4", true},
	"gre-key": {28, "IP externa 20 + GRE 4 + clave 4", true},
	"nat-t":   {8, "UDP 4500 8", false},
	"vxlan":   {50, "IP externa 20 + UDP 8 + VXLAN 8 + Ethernet interna 14", true},
	"lisp":    {36, "IP externa 20 + UDP 8 + LISP 8", true},
	"pppoe":   {8, "PPPoE 6 + PPP 2", false},
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
		r.Notes = append(r.Notes, fmt.Sprintf("IPv6 exige al menos 1280 bytes de MTU y quedan %d: el túnel no sirve para IPv6 sin subir la MTU física.", r.Effective))
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
	add := func(name, detail string, bytes int) {
		avail -= bytes
		r.Layers = append(r.Layers, MTULayer{Layer: name, Detail: detail, Bytes: bytes, Remaining: avail})
	}
	for i, raw := range stack {
		f := strings.Split(strings.ToLower(strings.TrimSpace(raw)), ":")
		name := f[0]
		// NAT-T es el UDP 4500 que envuelve al ESP: solo vale justo por fuera de él.
		if name == "nat-t" && (i+1 >= len(stack) || !strings.HasPrefix(strings.ToLower(strings.TrimSpace(stack[i+1])), "esp-")) {
			return r, errors.New("nat-t va inmediatamente antes (por fuera) de una capa esp-tunnel o esp-transport")
		}
		if s, ok := simpleLayers[name]; ok && len(f) == 1 && (!lifted || s.outerIP) {
			b, d := s.bytes, s.detail
			if s.outerIP && lifted { // su IP quedó delante del ESP de transporte
				b, d, lifted = b-20, strings.Replace(d, "IP externa 20", "IP externa (ya contada en ESP)", 1), false
			}
			add(name, d, b)
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
			add(name, fmt.Sprintf("%d etiqueta(s) × 4", n), 4*n)
		case "dot1q", "qinq":
			b := map[string]int{"dot1q": 4, "qinq": 8}[name]
			if inL2 {
				add(name, fmt.Sprintf("etiqueta en la trama interna %d", b), b)
			} else {
				add(name, "fuera de la MTU IP: la trama crece, la MTU IP no", 0)
				r.Notes = append(r.Notes, fmt.Sprintf("%s en el enlace físico no resta MTU IP (la trama crece a %d); solo resta si el equipo intermedio limita la trama a 1518.", name, phys+18+b))
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
			ipLabel := "IP externa 20"
			switch name {
			case "esp-transport":
				ipLabel, lifted, liftIdx = "IP del paquete protegido 20 (fuera del cifrado)", true, len(r.Layers)
			case "getvpn":
				ipLabel = "IP copiada del original 20 (preservación de cabecera)"
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
			d := fmt.Sprintf("%s + ESP 8 + IV %d + cola 2 + ICV %d", ipLabel, c.iv, icv)
			if tbar {
				d += " + metadatos TBAR 12"
			}
			d += fmt.Sprintf(" + alineación %d (bloque de %d)", align, c.block)
			add(raw, d, avail-(ct-2))
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
		last.Detail = strings.Replace(last.Detail, "IP del paquete protegido 20 (fuera del cifrado)", "IP del paquete protegido (es la suya)", 1)
	}
	r.Effective, r.Overhead = avail, phys-avail
	if ipsec {
		r.Notes = append(r.Notes, "Con ESP un byte más de carga puede costar un bloque entero de relleno: la cifra es exacta para esta MTU física. Si la ruta no se conoce, Cisco sugiere ip mtu 1400 / adjust-mss 1360.")
	}
	if vxlan {
		r.Notes = append(r.Notes, "VXLAN no fragmenta: sube la MTU del underlay en vez de bajar la de los hosts.")
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
	t := Table{Title: fmt.Sprintf("Desglose sobre MTU física %d", r.Physical), Head: []string{"Capa", "Detalle", "Bytes", "MTU restante"}}
	for _, l := range r.Layers {
		t.Rows = append(t.Rows, []string{l.Layer, l.Detail, strconv.Itoa(l.Bytes), strconv.Itoa(l.Remaining)})
	}
	inner := "IPv4 + TCP 40"
	if r.InnerIPv6 {
		inner = "IPv6 + TCP 60"
	}
	need := ""
	if r.PhysicalFor1500 > 0 {
		need = strconv.Itoa(r.PhysicalFor1500)
	}
	res := kv("Resultado", "Sobrecarga total", strconv.Itoa(r.Overhead), "MTU efectiva", strconv.Itoa(r.Effective),
		"ip mtu", strconv.Itoa(r.IPMTU), "ip tcp adjust-mss ("+inner+")", strconv.Itoa(r.MSS), "MTU física para 1500 sin fragmentar", need)
	return Report{Tables: []Table{t, res}, Notes: r.Notes}
}
