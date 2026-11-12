package fleet

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
	ID       int       `json:"id"`
	Parent   int       `json:"parent"`
	Device   string    `json:"device"`
	Via      string    `json:"via,omitempty"`
	OutIf    string    `json:"out_if,omitempty"`
	ECMP     bool      `json:"ecmp,omitempty"`
	Route    string    `json:"route,omitempty"`
	Segment  *Segment  `json:"segment,omitempty"` // tramo L2 por el que se llegó
	Final    *Segment  `json:"final,omitempty"`   // tramo L2 hasta el destino (último salto)
	Status   string    `json:"status"`
	Reason   string    `json:"reason,omitempty"`
	ReasonTx i18n.Text `json:"-"`
	Source   string    `json:"source,omitempty"`
	At       time.Time `json:"at"`
}

type PathResult struct {
	Src        string      `json:"src"`
	Dst        string      `json:"dst"`
	Hops       []PathHop   `json:"hops"`
	Arrived    bool        `json:"arrived"`
	Warnings   []string    `json:"warnings"`
	WarningsTx []i18n.Text `json:"-"`
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
	w.tx("fleet.warn.global_only")
	res := PathResult{Src: strings.TrimSpace(src), Dst: strings.TrimSpace(dst)}
	sa, ok1 := f.endpoint(src)
	da, ok2 := f.endpoint(dst)
	if !ok1 || !ok2 {
		w.tx("fleet.warn.bad_endpoints", "src", src, "dst", dst)
		res.Warnings, res.WarningsTx = w.list, w.txs
		return res
	}
	p := &pather{f: f, w: w, g: f.gather(w), rt: map[string]rtab{}, owners: map[string]*Dev{}, res: &res, dst: da}
	for _, d := range f.Devs {
		if routes, e, ok := read(w, d, "show ip route", iosxe.ParseRoute); ok {
			p.rt[d.Key] = rtab{routes, "show ip route", e.At}
			for _, ln := range iosxe.RouteUnread(e.Text) {
				w.tx("fleet.warn.route_unread", "dev", d.Name, "line", strings.TrimSpace(ln))
			}
		} else if routes, e, ok := read(w, d, "show ip cef", iosxe.ParseCEF); ok {
			p.rt[d.Key] = rtab{routes, "show ip cef", e.At}
			w.tx("fleet.warn.cef_fallback", "dev", d.Name)
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
		res.Hops = []PathHop{{ID: 0, Parent: -1, Device: sa.String(), Status: "cut"}}
		i18n.Put(&res.Hops[0].Reason, &res.Hops[0].ReasonTx, "fleet.reason.no_source", "src", sa)
		res.Warnings, res.WarningsTx = w.list, w.txs
		return res
	}
	if len(starts) > 1 {
		w.tx("fleet.warn.many_gateways", "src", sa, "n", len(starts), "first", starts[0].Name)
	}
	p.walk(starts[0], -1, map[string]bool{}, nil)
	for _, h := range res.Hops {
		if h.Status == "arrived" {
			res.Arrived = true
		}
	}
	res.Warnings, res.WarningsTx = w.list, w.txs
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

func (p *pather) cut(id int, key string, kv ...any) {
	h := &p.res.Hops[id]
	h.Status = "cut"
	i18n.Put(&h.Reason, &h.ReasonTx, key, kv...)
}

// cutTx es cut con el motivo ya armado.
func (p *pather) cutTx(id int, why i18n.Text) {
	h := &p.res.Hops[id]
	h.Status, h.Reason, h.ReasonTx = "cut", why.In(i18n.Es), why
}

func (p *pather) arrived(id int, key string, kv ...any) {
	h := &p.res.Hops[id]
	h.Status = "arrived"
	i18n.Put(&h.Reason, &h.ReasonTx, key, kv...)
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
		p.w.tx("fleet.warn.no_arp_l2", "dev", d.Name, "ip", ip)
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
		p.w.tx("fleet.warn.path_hops", "max", maxPathHops)
		p.cut(id, "fleet.reason.too_many_hops")
		return
	}
	if p.owners[p.dst.String()] == d {
		p.arrived(id, "fleet.reason.local_dest")
		return
	}
	visited = copySet(visited)
	visited[d.Key] = true
	if rt.routes == nil {
		p.cut(id, "fleet.reason.no_routes", "dev", d.Name)
		return
	}
	r, ok := iosxe.LongestMatch(rt.routes, p.dst)
	if !ok {
		p.cut(id, "fleet.reason.no_route", "dst", p.dst, "dev", d.Name)
		return
	}
	p.res.Hops[id].Route = fmt.Sprintf("%s %s", r.Code, r.Prefix)
	if discards(r) {
		p.cut(id, "fleet.reason.discard", "prefix", r.Prefix, "dev", d.Name)
		return
	}
	if len(r.Hops) == 0 {
		p.cut(id, "fleet.reason.no_nexthop", "prefix", r.Prefix, "dev", d.Name)
		return
	}
	if r.Connected {
		iface := r.Hops[0].Iface
		if _, ok := p.arpMAC(d, p.dst.String()); ok {
			seg := p.segment(d, iface, p.dst.String())
			p.res.Hops[id].Final = seg
			if n := len(seg.L2); seg.L2End == "access" && n > 0 {
				acc := seg.L2[n-1]
				p.arrived(id, "fleet.reason.access_port", "dev", acc.Device, "port", acc.Port, "vlan", acc.VLAN)
				return
			}
			p.cut(id, "fleet.reason.l2_ended", "end", seg.L2End)
			return
		}
		p.w.tx("fleet.warn.no_arp", "dev", d.Name, "ip", p.dst)
		p.res.Hops[id].Final = &Segment{Interface: iface, L2End: "no-arp"}
		p.cut(id, "fleet.reason.no_arp", "iface", iface)
		return
	}
	for _, nh0 := range r.Hops {
		nh, why := p.resolveHop(d, rt.routes, nh0)
		if !why.Empty() {
			cid := p.add(PathHop{Parent: id, Device: nh0.IP, Via: nh0.IP})
			p.cutTx(cid, why)
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
			p.cut(cid, "fleet.reason.no_evidence", "nh", nh.IP)
		case visited[next.Key]:
			cid := p.add(PathHop{Parent: id, Device: next.Name, Via: in.Via, OutIf: in.OutIf, ECMP: in.ECMP, Segment: in.Segment})
			p.cut(cid, "fleet.reason.routing_loop", "dev", next.Name)
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
func (p *pather) resolveHop(d *Dev, routes []iosxe.Route, nh iosxe.NextHop) (iosxe.NextHop, i18n.Text) {
	cur := nh
	for range maxRecurse {
		if cur.Iface != "" {
			if cur.IP != nh.IP {
				p.w.tx("fleet.warn.recursive", "dev", d.Name, "nh", nh.IP, "to", cur.IP, "iface", cur.Iface)
			}
			return cur, i18n.Text{}
		}
		addr, err := netip.ParseAddr(cur.IP)
		if err != nil {
			return nh, i18n.Tx("fleet.reason.rec_not_ip", "ip", cur.IP)
		}
		r, ok := iosxe.LongestMatch(routes, addr)
		switch {
		case !ok:
			return nh, i18n.Tx("fleet.reason.rec_no_route", "ip", cur.IP, "dev", d.Name)
		case r.Connected:
			cur.Iface = r.Hops[0].Iface
		case len(r.Hops) == 0:
			return nh, i18n.Tx("fleet.reason.rec_no_nexthop", "ip", cur.IP)
		default:
			if len(r.Hops) > 1 {
				p.w.tx("fleet.warn.recursive_ecmp", "dev", d.Name, "nh", cur.IP, "n", len(r.Hops))
			}
			cur = r.Hops[0]
		}
	}
	return nh, i18n.Tx("fleet.reason.rec_depth", "n", maxRecurse)
}

func copySet(m map[string]bool) map[string]bool {
	o := make(map[string]bool, len(m)+1)
	for k, v := range m {
		o[k] = v
	}
	return o
}
