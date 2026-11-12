package fleet

import (
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Hit es un lugar donde aparece lo buscado, con su evidencia.
type Hit struct {
	Kind   string    `json:"kind"` // arp, mac-table, dhcp-snooping, cdp, lldp, interface, device
	Device string    `json:"device"`
	Port   string    `json:"port,omitempty"`
	VLAN   string    `json:"vlan,omitempty"`
	MAC    string    `json:"mac,omitempty"`
	IP     string    `json:"ip,omitempty"`
	Name   string    `json:"name,omitempty"` // vecino u otro nombre
	Source string    `json:"source"`
	At     time.Time `json:"at"`
}

type FindResult struct {
	Query    string         `json:"query"`
	Mode     string         `json:"mode"` // mac, ip, name
	Hits     []Hit          `json:"hits"`
	Devices  int            `json:"devices"`
	Checked  map[string]int `json:"checked"` // equipos con dato por fuente consultada
	Warnings []string       `json:"warnings"`
}

type tag struct {
	Dev *Dev
	Src string
	At  time.Time
}

// l2 reúne las tablas de capa 2 y los vecinos de toda la flota.
type l2 struct {
	arp []struct {
		tag
		iosxe.ARP
	}
	mac []struct {
		tag
		iosxe.MACEntry
	}
	dhcp []struct {
		tag
		iosxe.DHCPBinding
	}
	nbr []struct {
		tag
		iosxe.Neighbor
	}
	ifs []struct {
		tag
		iosxe.Iface
	}
	brief []struct {
		tag
		iosxe.IPBrief
	}
	have map[string]map[string]bool     // comando → equipos con evidencia utilizable
	pc   map[string]map[string][]string // equipo → Po → miembros
	stat map[string]map[string]iosxe.IfStatus
}

func gatherRows[T any](g *l2, w *ws, f *Fleet, cmd string, p func(string) ([]T, bool), add func(tag, T)) {
	for _, d := range f.Devs {
		rows, e, ok := read(w, d, cmd, p)
		for _, r := range rows {
			add(tag{d, cmd, e.At}, r)
		}
		if ok {
			if g.have[cmd] == nil {
				g.have[cmd] = map[string]bool{}
			}
			g.have[cmd][d.Key] = true
		}
	}
}

func (f *Fleet) gather(w *ws) *l2 {
	g := &l2{have: map[string]map[string]bool{}, pc: map[string]map[string][]string{}, stat: map[string]map[string]iosxe.IfStatus{}}
	gatherRows(g, w, f, "show ip arp", iosxe.ParseARP, func(t tag, r iosxe.ARP) {
		g.arp = append(g.arp, struct {
			tag
			iosxe.ARP
		}{t, r})
	})
	gatherRows(g, w, f, "show mac address-table", iosxe.ParseMACTable, func(t tag, r iosxe.MACEntry) {
		g.mac = append(g.mac, struct {
			tag
			iosxe.MACEntry
		}{t, r})
	})
	gatherRows(g, w, f, "show ip dhcp snooping binding", iosxe.ParseDHCPSnooping, func(t tag, r iosxe.DHCPBinding) {
		g.dhcp = append(g.dhcp, struct {
			tag
			iosxe.DHCPBinding
		}{t, r})
	})
	gatherRows(g, w, f, "show cdp neighbors detail", iosxe.ParseCDP, func(t tag, r iosxe.Neighbor) {
		g.nbr = append(g.nbr, struct {
			tag
			iosxe.Neighbor
		}{t, r})
	})
	gatherRows(g, w, f, "show lldp neighbors detail", iosxe.ParseLLDP, func(t tag, r iosxe.Neighbor) {
		g.nbr = append(g.nbr, struct {
			tag
			iosxe.Neighbor
		}{t, r})
	})
	gatherRows(g, w, f, "show interfaces", iosxe.ParseInterfaces, func(t tag, r iosxe.Iface) {
		g.ifs = append(g.ifs, struct {
			tag
			iosxe.Iface
		}{t, r})
	})
	gatherRows(g, w, f, "show ip interface brief", iosxe.ParseIPBrief, func(t tag, r iosxe.IPBrief) {
		if r.IP == "unassigned" { // el parser las trae; el rastreo solo busca por dirección
			return
		}
		g.brief = append(g.brief, struct {
			tag
			iosxe.IPBrief
		}{t, r})
	})
	for _, d := range f.Devs {
		if e, ok := d.Get("show etherchannel summary"); ok && !rejected(e) {
			g.pc[d.Key] = iosxe.ParsePortChannels(e.Text)
		}
		if rows, _, ok := read(w, d, "show interfaces status", iosxe.ParseIfStatus); ok {
			g.stat[d.Key] = map[string]iosxe.IfStatus{}
			for _, r := range rows {
				g.stat[d.Key][r.Port] = r
			}
		}
	}
	return g
}

func ipOnly(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().String()
	}
	return s
}

// Find cruza ARP, tabla MAC, CDP/LLDP, DHCP snooping e interfaces para una IP, MAC (cualquier notación) o nombre.
func (f *Fleet) Find(q string) FindResult {
	w := f.newWS()
	g := f.gather(w)
	q = strings.TrimSpace(q)
	res := FindResult{Query: q, Devices: len(f.Devs), Checked: map[string]int{}}
	add := func(h Hit, t tag) {
		h.Device, h.Source, h.At = t.Dev.Name, t.Src, t.At
		res.Hits = append(res.Hits, h)
	}
	macs := map[string]bool{}
	byMAC := func(m string) {
		for _, r := range g.mac {
			if r.MAC == m {
				add(Hit{Kind: "mac-table", Port: r.Port, VLAN: r.VLAN, MAC: m}, r.tag)
			}
		}
	}
	if m, ok := iosxe.NormMAC(q); ok {
		res.Mode = "mac"
		macs[m] = true
		for _, r := range g.arp {
			if r.MAC == m {
				add(Hit{Kind: "arp", Port: r.Iface, MAC: m, IP: r.IP}, r.tag)
			}
		}
		for _, r := range g.dhcp {
			if r.MAC == m {
				add(Hit{Kind: "dhcp-snooping", Port: r.Iface, VLAN: r.VLAN, MAC: m, IP: r.IP}, r.tag)
			}
		}
		for _, r := range g.ifs {
			if r.MAC == m {
				add(Hit{Kind: "interface", Port: r.Name, MAC: m, IP: firstIP(r.IPs)}, r.tag)
			}
		}
		byMAC(m)
	} else if a, err := netip.ParseAddr(q); err == nil {
		res.Mode = "ip"
		ip := a.String()
		for _, r := range g.arp {
			if r.IP == ip {
				macs[r.MAC] = true
				add(Hit{Kind: "arp", Port: r.Iface, MAC: r.MAC, IP: ip}, r.tag)
			}
		}
		for _, r := range g.dhcp {
			if r.IP == ip {
				macs[r.MAC] = true
				add(Hit{Kind: "dhcp-snooping", Port: r.Iface, VLAN: r.VLAN, MAC: r.MAC, IP: ip}, r.tag)
			}
		}
		for _, r := range g.nbr {
			if r.MgmtIP == ip {
				add(Hit{Kind: r.Protocol, Port: r.LocalIf, Name: r.Device, IP: ip}, r.tag)
			}
		}
		for _, r := range g.ifs {
			for _, x := range r.IPs {
				if ipOnly(x) == ip {
					add(Hit{Kind: "interface", Port: r.Name, MAC: r.MAC, IP: ip}, r.tag)
				}
			}
		}
		for _, r := range g.brief {
			if r.IP == ip {
				add(Hit{Kind: "interface", Port: r.Iface, IP: ip}, r.tag)
			}
		}
		for _, d := range f.Devs {
			if d.IP == ip {
				add(Hit{Kind: "device", IP: ip, Name: d.Key}, tag{d, "carpeta de Patrol", latest(d)})
			}
		}
		for m := range macs {
			byMAC(m)
		}
	} else {
		res.Mode = "name"
		n := strings.ToLower(q)
		for _, d := range f.Devs {
			if strings.Contains(strings.ToLower(d.Name), n) || strings.Contains(strings.ToLower(d.Key), n) {
				add(Hit{Kind: "device", IP: d.IP, Name: d.Key}, tag{d, "carpeta de Patrol", latest(d)})
			}
		}
		for _, r := range g.nbr {
			if strings.Contains(strings.ToLower(r.Device), n) {
				add(Hit{Kind: r.Protocol, Port: r.LocalIf, Name: r.Device, IP: r.MgmtIP}, r.tag)
			}
		}
	}
	sort.SliceStable(res.Hits, func(i, j int) bool {
		a, b := res.Hits[i], res.Hits[j]
		if a.Device != b.Device {
			return a.Device < b.Device
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Port < b.Port
	})
	srcs := map[string][]string{
		"mac":  {"show ip arp", "show mac address-table", "show ip dhcp snooping binding", "show interfaces"},
		"ip":   {"show ip arp", "show mac address-table", "show ip dhcp snooping binding", "show cdp neighbors detail", "show lldp neighbors detail", "show interfaces", "show ip interface brief"},
		"name": {"show cdp neighbors detail", "show lldp neighbors detail"},
	}[res.Mode]
	for _, c := range srcs {
		res.Checked[c] = len(g.have[c])
		var miss []string
		for _, d := range f.Devs {
			if !g.have[c][d.Key] {
				miss = append(miss, d.Name)
			}
		}
		if len(miss) > 0 {
			w.add("sin %s: %s (la búsqueda no cubre esos equipos en esa fuente)", c, strings.Join(miss, ", "))
		}
	}
	res.Warnings = w.list
	return res
}

func firstIP(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return ipOnly(l[0])
}

func latest(d *Dev) time.Time {
	var t time.Time
	for _, e := range d.ev {
		if e.At.After(t) {
			t = e.At
		}
	}
	return t
}

// ---- rastreo L2 ----

type TraceHop struct {
	Device       string    `json:"device"`
	Port         string    `json:"port"`
	VLAN         string    `json:"vlan,omitempty"`
	Neighbor     string    `json:"neighbor,omitempty"`
	NeighborPort string    `json:"neighbor_port,omitempty"`
	Note         string    `json:"note,omitempty"`
	Source       string    `json:"source"`
	At           time.Time `json:"at"`
}

// Fin del rastreo: access, self (la MAC es del propio equipo), loop, no-neighbor
// (vecino sin evidencia), trunk-sin-vecino (trunk o Po sin CDP/LLDP: no es acceso),
// no-mac (el vecino no la tiene), not-found, max.
type TraceResult struct {
	Query    string     `json:"query"`
	MAC      string     `json:"mac,omitempty"`
	IP       string     `json:"ip,omitempty"`
	Hops     []TraceHop `json:"hops"`
	End      string     `json:"end"`
	Access   *TraceHop  `json:"access,omitempty"`
	Warnings []string   `json:"warnings"`
}

const maxTrace = 32

func (g *l2) macEntry(d *Dev, mac, vlan string) (struct {
	tag
	iosxe.MACEntry
}, bool) {
	var best struct {
		tag
		iosxe.MACEntry
	}
	ok := false
	for _, r := range g.mac {
		if r.Dev != d || r.MAC != mac {
			continue
		}
		if !ok || (vlan != "" && r.VLAN == vlan && best.VLAN != vlan) || (r.Type == "DYNAMIC" && best.Type != "DYNAMIC" && (vlan == "" || r.VLAN == best.VLAN)) {
			best, ok = r, true
		}
	}
	return best, ok
}

// neighborOf busca el vecino de un puerto; un port-channel mira a sus miembros.
func (g *l2) neighborOf(d *Dev, port string) (iosxe.Neighbor, bool) {
	ports := map[string]bool{port: true}
	for _, m := range g.pc[d.Key][port] {
		ports[m] = true
	}
	var first *iosxe.Neighbor
	for i, r := range g.nbr {
		if r.Dev == d && ports[r.LocalIf] {
			if r.Infra() { // CDP y LLDP pueden dar dos vecinos: manda el equipo de red
				return r.Neighbor, true
			}
			if first == nil {
				first = &g.nbr[i].Neighbor
			}
		}
	}
	if first != nil {
		return *first, true
	}
	return iosxe.Neighbor{}, false
}

func (f *Fleet) resolve(n iosxe.Neighbor) *Dev {
	for _, d := range f.Devs {
		if n.MgmtIP != "" && d.IP == n.MgmtIP || shortName(n.Device) == shortName(d.Name) {
			return d
		}
	}
	return nil
}

// walk sigue la MAC desde start (nil = elige).
func (f *Fleet) walk(g *l2, w *ws, mac string, start *Dev) (hops []TraceHop, end string, access *TraceHop) {
	if start == nil {
		var cands []*Dev
		for _, d := range f.Devs {
			if e, ok := g.macEntry(d, mac, ""); ok && e.Port != "CPU" {
				cands = append(cands, d)
			}
		}
		for _, d := range cands { // preferir quien la ve por un enlace a otro equipo
			e, _ := g.macEntry(d, mac, "")
			if _, has := g.neighborOf(d, e.Port); has && start == nil {
				start = d
			}
		}
		if start == nil && len(cands) > 0 {
			start = cands[0]
		}
		if start == nil {
			w.add("la MAC %s no aparece en ninguna tabla de direcciones de la flota", mac)
			return nil, "not-found", nil
		}
	}
	visited := map[string]bool{}
	vlan := ""
	for cur := start; len(hops) < maxTrace; {
		e, ok := g.macEntry(cur, mac, vlan)
		if !ok {
			w.add("%s no tiene la MAC %s en su tabla (la entrada pudo expirar o la evidencia es de otra hora)", cur.Name, mac)
			return hops, "no-mac", nil
		}
		h := TraceHop{Device: cur.Name, Port: e.Port, VLAN: e.VLAN, Source: "show mac address-table", At: e.At}
		if e.Port == "CPU" {
			h.Note = "la MAC es del propio equipo"
			return append(hops, h), "self", nil
		}
		if k := cur.Key + "|" + e.Port; visited[k] {
			w.add("bucle en el seguimiento: %s %s ya se visitó; se corta (revisa STP o evidencia de horas distintas)", cur.Name, e.Port)
			h.Note = "bucle"
			return append(hops, h), "loop", nil
		} else {
			visited[k] = true
		}
		nb, has := g.neighborOf(cur, e.Port)
		if has && !nb.Infra() { // teléfono, AP u host publicado por CDP/LLDP: el puerto es de acceso
			h.Neighbor, h.Note = nb.Device, "puerto de acceso (equipo extremo: "+strings.Join(nb.Capabilities, " ")+")"
			hops = append(hops, h)
			return hops, "access", &hops[len(hops)-1]
		}
		if !has {
			if st := g.stat[cur.Key][e.Port]; strings.HasPrefix(e.Port, "Po") || st.VLAN == "trunk" {
				h.Note = "trunk sin vecino CDP/LLDP"
				w.add("%s %s es un trunk o port-channel sin vecino CDP/LLDP: puede faltar evidencia de un equipo; el rastreo se corta ahí", cur.Name, e.Port)
				return append(hops, h), "trunk-sin-vecino", nil
			}
			h.Note = "puerto de acceso"
			hops = append(hops, h)
			return hops, "access", &hops[len(hops)-1]
		}
		h.Neighbor, h.NeighborPort = nb.Device, nb.RemoteIf
		hops = append(hops, h)
		next := f.resolve(nb)
		if next == nil {
			w.add("el vecino %s (%s) no tiene evidencia en la flota: el rastreo se corta ahí", nb.Device, nb.MgmtIP)
			return hops, "no-neighbor", nil
		}
		cur, vlan = next, e.VLAN
	}
	w.add("el rastreo pasó de %d saltos; se corta", maxTrace)
	return hops, "max", nil
}

// Trace sigue una MAC (o la MAC de una IP) hasta el puerto de acceso.
func (f *Fleet) Trace(q string) TraceResult {
	w := f.newWS()
	g := f.gather(w)
	res := TraceResult{Query: strings.TrimSpace(q)}
	if m, ok := iosxe.NormMAC(q); ok {
		res.MAC = m
	} else if a, err := netip.ParseAddr(strings.TrimSpace(q)); err == nil {
		res.IP = a.String()
		var at time.Time
		macs := map[string]bool{}
		for _, r := range g.arp {
			if r.IP == res.IP {
				macs[r.MAC] = true
				if r.At.After(at) {
					at, res.MAC = r.At, r.MAC
				}
			}
		}
		if len(macs) > 1 {
			w.add("la IP %s tiene %d MAC distintas en el ARP de la flota; se usa la de la evidencia más reciente (%s)", res.IP, len(macs), res.MAC)
		}
		if res.MAC == "" {
			w.add("ningún equipo tiene la IP %s en su ARP: no se puede saber su MAC", res.IP)
			res.End, res.Warnings = "not-found", w.list
			return res
		}
	} else {
		res.End = "not-found"
		w.add("%q no es una MAC ni una IP", q)
		res.Warnings = w.list
		return res
	}
	res.Hops, res.End, res.Access = f.walk(g, w, res.MAC, nil)
	seen := map[string]bool{}
	for _, h := range res.Hops {
		seen[h.Device] = true
	}
	for _, r := range g.mac {
		if r.MAC == res.MAC && !seen[r.Dev.Name] && r.Port != "CPU" {
			w.add("la MAC también aparece en %s puerto %s, fuera de este recorrido", r.Dev.Name, r.Port)
			seen[r.Dev.Name] = true
		}
	}
	res.Warnings = w.list
	return res
}
