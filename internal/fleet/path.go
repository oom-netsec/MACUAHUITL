package fleet

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Segment es el tramo L2 entre dos saltos L3 (o hasta el destino).
type Segment struct {
	Interface string     `json:"interface"`
	Mode      string     `json:"mode,omitempty"` // svi, routed, trunk, access
	VLAN      string     `json:"vlan,omitempty"`
	L2        []TraceHop `json:"l2,omitempty"`
	L2End     string     `json:"l2_end,omitempty"`
}

// PathHop es un equipo alcanzado. Parent -1 es la raíz. Via, OutIf y Segment
// describen cómo se llegó desde el padre. Status: ok, arrived o cut.
type PathHop struct {
	ID      int       `json:"id"`
	Parent  int       `json:"parent"`
	Device  string    `json:"device"`
	Via     string    `json:"via,omitempty"`
	OutIf   string    `json:"out_if,omitempty"`
	ECMP    bool      `json:"ecmp,omitempty"`
	Route   string    `json:"route,omitempty"`
	Segment *Segment  `json:"segment,omitempty"` // tramo L2 por el que se llegó
	Final   *Segment  `json:"final,omitempty"`   // tramo L2 hasta el destino (último salto)
	Status  string    `json:"status"`
	Reason  string    `json:"reason,omitempty"`
	Source  string    `json:"source,omitempty"`
	At      time.Time `json:"at"`
}

type PathResult struct {
	Src      string    `json:"src"`
	Dst      string    `json:"dst"`
	Hops     []PathHop `json:"hops"`
	Arrived  bool      `json:"arrived"`
	Warnings []string  `json:"warnings"`
}

type rtab struct {
	routes []iosxe.Route
	src    string
	at     time.Time
}

const maxPathHops = 64

type pather struct {
	f      *Fleet
	w      *ws
	g      *l2
	rt     map[string]rtab
	owners map[string]*Dev
	res    *PathResult
	dst    netip.Addr
}

func (f *Fleet) endpoint(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a, true
	}
	for _, d := range f.Devs {
		if strings.EqualFold(shortName(d.Name), shortName(s)) || strings.EqualFold(d.Key, s) {
			a, err := netip.ParseAddr(d.IP)
			return a, err == nil
		}
	}
	return netip.Addr{}, false
}

// Path sigue la ruta L3 de src a dst con las tablas de rutas recolectadas.
func (f *Fleet) Path(src, dst string) PathResult {
	w := f.newWS()
	w.add("solo tabla global; VRF, PBR y NAT no modelados")
	res := PathResult{Src: strings.TrimSpace(src), Dst: strings.TrimSpace(dst)}
	sa, ok1 := f.endpoint(src)
	da, ok2 := f.endpoint(dst)
	if !ok1 || !ok2 {
		w.add("origen y destino deben ser IP o el nombre de un equipo de la flota (%q → %q)", src, dst)
		res.Warnings = w.list
		return res
	}
	p := &pather{f: f, w: w, g: f.gather(w), rt: map[string]rtab{}, owners: map[string]*Dev{}, res: &res, dst: da}
	for _, d := range f.Devs {
		if routes, e, ok := read(w, d, "show ip route", iosxe.ParseRoute); ok {
			p.rt[d.Key] = rtab{routes, "show ip route", e.At}
			for _, ln := range iosxe.RouteUnread(e.Text) {
				w.add("%s · show ip route: línea con forma de ruta no leída, la tabla puede estar incompleta: %q", d.Name, strings.TrimSpace(ln))
			}
		} else if routes, e, ok := read(w, d, "show ip cef", iosxe.ParseCEF); ok {
			p.rt[d.Key] = rtab{routes, "show ip cef", e.At}
			w.add("%s: sin show ip route; se usa show ip cef (sin distancia ni códigos de protocolo)", d.Name)
		}
		p.owners[d.IP] = d
		for _, r := range p.rt[d.Key].routes {
			if r.Connected && r.Prefix.IsSingleIP() && r.Code == "L" {
				p.owners[r.Prefix.Addr().String()] = d
			}
		}
	}
	for _, r := range p.g.brief {
		p.owners[r.IP] = r.Dev
	}
	for _, r := range p.g.ifs {
		for _, x := range r.IPs {
			p.owners[ipOnly(x)] = r.Dev
		}
	}
	starts := p.gateways(sa)
	if len(starts) == 0 {
		res.Hops = []PathHop{{ID: 0, Parent: -1, Device: sa.String(), Status: "cut", Reason: "ningún equipo de la flota tiene una ruta conectada al origen " + sa.String() + " (sin evidencia del equipo de origen)"}}
		res.Warnings = w.list
		return res
	}
	if len(starts) > 1 {
		w.add("el origen %s tiene %d puertas de enlace en la flota (%s...); se sigue la primera con ARP del origen", sa, len(starts), starts[0].Name)
	}
	p.walk(starts[0], -1, map[string]bool{}, nil)
	for _, h := range res.Hops {
		if h.Status == "arrived" {
			res.Arrived = true
		}
	}
	res.Warnings = w.list
	return res
}

// gateways: dueños del origen, o equipos con una red conectada que lo contiene (con ARP del origen primero).
func (p *pather) gateways(src netip.Addr) []*Dev {
	if d := p.owners[src.String()]; d != nil {
		return []*Dev{d}
	}
	var withARP, other []*Dev
	for _, d := range p.f.Devs {
		for _, r := range p.rt[d.Key].routes {
			if r.Connected && r.Code != "L" && r.Prefix.Contains(src) && !r.Prefix.IsSingleIP() {
				has := false
				for _, a := range p.g.arp {
					has = has || a.Dev == d && a.IP == src.String()
				}
				if has {
					withARP = append(withARP, d)
				} else {
					other = append(other, d)
				}
				break
			}
		}
	}
	return append(withARP, other...)
}

func (p *pather) add(h PathHop) int {
	h.ID = len(p.res.Hops)
	p.res.Hops = append(p.res.Hops, h)
	return h.ID
}

func (p *pather) cut(id int, why string) {
	p.res.Hops[id].Status, p.res.Hops[id].Reason = "cut", why
}

func (p *pather) arpMAC(d *Dev, ip string) (string, bool) {
	for _, a := range p.g.arp {
		if a.Dev == d && a.IP == ip {
			return a.MAC, true
		}
	}
	return "", false
}

// segment arma el tramo L2 de d por iface hacia ip.
func (p *pather) segment(d *Dev, iface, ip string) *Segment {
	s := &Segment{Interface: iface}
	switch {
	case strings.HasPrefix(strings.ToLower(iface), "vlan"):
		s.Mode, s.VLAN = "svi", iface[4:]
	case p.g.stat[d.Key][iface].VLAN == "routed":
		s.Mode = "routed"
	case p.g.stat[d.Key][iface].VLAN == "trunk":
		s.Mode = "trunk"
	}
	mac, ok := p.arpMAC(d, ip)
	if !ok {
		s.L2End = "no-arp"
		p.w.add("%s no tiene %s en su ARP: no se puede ubicar el tramo L2", d.Name, ip)
		return s
	}
	s.L2, s.L2End, _ = p.f.walk(p.g, p.w, mac, d)
	return s
}

func (p *pather) walk(d *Dev, parent int, visited map[string]bool, in *PathHop) {
	rt := p.rt[d.Key]
	h := PathHop{Parent: parent, Device: d.Name, Status: "ok", Source: rt.src, At: rt.at}
	if in != nil {
		h.Via, h.OutIf, h.ECMP, h.Segment = in.Via, in.OutIf, in.ECMP, in.Segment
	}
	id := p.add(h)
	if len(p.res.Hops) > maxPathHops {
		p.w.add("el camino pasó de %d saltos (ramas ECMP); se corta", maxPathHops)
		p.cut(id, "demasiados saltos")
		return
	}
	if p.owners[p.dst.String()] == d {
		p.res.Hops[id].Status, p.res.Hops[id].Reason = "arrived", "el destino es una interfaz de este equipo"
		return
	}
	visited = copySet(visited)
	visited[d.Key] = true
	if rt.routes == nil {
		p.cut(id, "sin show ip route ni show ip cef de "+d.Name)
		return
	}
	r, ok := iosxe.LongestMatch(rt.routes, p.dst)
	if !ok {
		p.cut(id, "sin ruta a "+p.dst.String()+" en "+d.Name)
		return
	}
	p.res.Hops[id].Route = fmt.Sprintf("%s %s", r.Code, r.Prefix)
	if discards(r) {
		p.cut(id, "descartado (Null0/drop): la ruta "+r.Prefix.String()+" en "+d.Name+" no reenvía")
		return
	}
	if len(r.Hops) == 0 {
		p.cut(id, "la ruta "+r.Prefix.String()+" en "+d.Name+" no tiene siguiente salto ni interfaz")
		return
	}
	if r.Connected {
		iface := r.Hops[0].Iface
		if _, ok := p.arpMAC(d, p.dst.String()); ok {
			seg := p.segment(d, iface, p.dst.String())
			p.res.Hops[id].Final = seg
			if n := len(seg.L2); seg.L2End == "access" && n > 0 {
				acc := seg.L2[n-1]
				p.res.Hops[id].Status, p.res.Hops[id].Reason = "arrived", fmt.Sprintf("puerto de acceso %s %s VLAN %s", acc.Device, acc.Port, acc.VLAN)
				return
			}
			p.cut(id, "red conectada pero el rastreo L2 del destino terminó en: "+seg.L2End)
			return
		}
		p.w.add("%s no tiene %s en su ARP", d.Name, p.dst)
		p.res.Hops[id].Final = &Segment{Interface: iface, L2End: "no-arp"}
		p.cut(id, "red conectada ("+iface+") pero sin entrada ARP del destino: no se sabe en qué puerto está")
		return
	}
	for _, nh0 := range r.Hops {
		nh, why := p.resolveHop(d, rt.routes, nh0)
		if why != "" {
			cid := p.add(PathHop{Parent: id, Device: nh0.IP, Via: nh0.IP})
			p.cut(cid, "siguiente salto recursivo no resuelto: "+why)
			continue
		}
		iface := nh.Iface
		in := &PathHop{Via: nh.IP, OutIf: iface, ECMP: len(r.Hops) > 1}
		if iface != "" {
			in.Segment = p.segment(d, iface, nh.IP)
		}
		next := p.owners[nh.IP]
		switch {
		case next == nil:
			cid := p.add(PathHop{Parent: id, Device: nh.IP, Via: in.Via, OutIf: in.OutIf, ECMP: in.ECMP, Segment: in.Segment})
			p.cut(cid, "sin evidencia del siguiente equipo (el salto "+nh.IP+" no es de ningún equipo recolectado)")
		case visited[next.Key]:
			cid := p.add(PathHop{Parent: id, Device: next.Name, Via: in.Via, OutIf: in.OutIf, ECMP: in.ECMP, Segment: in.Segment})
			p.cut(cid, "bucle de enrutamiento: vuelve a "+next.Name)
		default:
			p.walk(next, id, visited, in)
		}
	}
}

// discards: la ruta sale por Null0 (resumen, estática de descarte o CEF drop).
func discards(r iosxe.Route) bool {
	for _, h := range r.Hops {
		if h.IP == "" && strings.HasPrefix(strings.ToLower(h.Iface), "null") {
			return true
		}
	}
	return false
}

const maxRecurse = 8

// resolveHop lleva un siguiente salto recursivo (iBGP a un loopback remoto) al
// salto conectado real con LPM sobre la tabla del mismo equipo. Si no se puede,
// devuelve el motivo: nunca se salta un equipo intermedio.
func (p *pather) resolveHop(d *Dev, routes []iosxe.Route, nh iosxe.NextHop) (iosxe.NextHop, string) {
	cur := nh
	for range maxRecurse {
		if cur.Iface != "" {
			if cur.IP != nh.IP {
				p.w.add("%s: el siguiente salto %s es recursivo; se resolvió a %s por %s", d.Name, nh.IP, cur.IP, cur.Iface)
			}
			return cur, ""
		}
		addr, err := netip.ParseAddr(cur.IP)
		if err != nil {
			return nh, "el salto " + cur.IP + " no es una IP"
		}
		r, ok := iosxe.LongestMatch(routes, addr)
		switch {
		case !ok:
			return nh, "sin ruta a " + cur.IP + " en " + d.Name
		case r.Connected:
			cur.Iface = r.Hops[0].Iface
		case len(r.Hops) == 0:
			return nh, "la ruta a " + cur.IP + " no tiene siguiente salto"
		default:
			if len(r.Hops) > 1 {
				p.w.add("%s: el salto recursivo %s tiene %d salidas ECMP; se sigue la primera", d.Name, cur.IP, len(r.Hops))
			}
			cur = r.Hops[0]
		}
	}
	return nh, "más de " + fmt.Sprint(maxRecurse) + " niveles de recursión"
}

func copySet(m map[string]bool) map[string]bool {
	o := make(map[string]bool, len(m)+1)
	for k, v := range m {
		o[k] = v
	}
	return o
}
