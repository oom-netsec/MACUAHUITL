package assist

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// El puerto de la sesión: el puerto físico (o el Port-channel) por donde entra la sesión SSH con el equipo. Cambiarlo (apagarlo, cambiarle la VLAN,
// el modo, la velocidad, ponerle un guard que lo errdisablee) corta el acceso y la reversa ya no llega. Se protege ese puerto exacto, no todos los
// de la VLAN de gestión: en un switch de fábrica todo está en la VLAN 1 y el laboratorio usa puertos libres de ella.
//
// Se descubre con lecturas encadenadas (cada una depende de la anterior, por eso el servicio las pide en rondas con SessionPortReads):
// show users (origen) → show ip arp ORIGEN y show ip route ORIGEN (siguiente salto: el propio origen si hay ARP de él, si no el gateway) →
// show ip arp SALTO (MAC e interfaz) → show mac address-table address MAC (puerto) → show etherchannel summary (si es un canal: sus miembros).
// Formatos de la documentación de Cisco, sin validar en laboratorio.

const showEtherchannelCmd = "show etherchannel summary"

// sessionPort es lo que se sabe del puerto de la sesión. known solo es true si se identificó con certeza un único puerto.
type sessionPort struct {
	known bool
	ports map[string]bool // nombres cortos en minúsculas: el puerto, su Port-channel y los miembros del canal
	vlan  string          // VLAN que lleva la sesión en ese puerto ("" si no se sabe)
	mac   string          // MAC del siguiente salto
}

// Con rutas de igual costo IOS marca con * solo un camino; los demás salen sin * (`10.1.1.6, from …` o, en una estática, la IP sola):
// se cuentan todos. La caché de redirect de un switch L2 tiene filas «IP  IP  …» con más columnas, que no casan.
var hopRe = regexp.MustCompile(`(?i)^(?:(?:\*\s*)?(\d+\.\d+\.\d+\.\d+)(?:,|$)|default gateway is\s+(\d+\.\d+\.\d+\.\d+))`)

// nextHopOf lee el gateway de `show ip route ORIGEN` (`* 10.1.1.2, from ..., via Vlan10`) o de un switch L2 (`Default gateway is X`).
// Sin salto, o con varios distintos (rutas de igual costo), no hay certeza.
func nextHopOf(route string) (netip.Addr, bool) {
	var hops []netip.Addr
	for _, l := range strings.Split(route, "\n") {
		if m := hopRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			if a, err := netip.ParseAddr(m[1] + m[2]); err == nil && !slices.Contains(hops, a) {
				hops = append(hops, a)
			}
		}
	}
	if len(hops) != 1 {
		return netip.Addr{}, false
	}
	return hops[0], true
}

func arpRow(text string, ip netip.Addr) (iosxe.ARP, bool) {
	rows, _ := iosxe.ParseARP(text)
	for _, r := range rows {
		if r.IP == ip.String() {
			return r, true
		}
	}
	return iosxe.ARP{}, false
}

func unread(outs map[string]string, cmds ...string) []string {
	var out []string
	for _, c := range cmds {
		if _, ok := outs[c]; !ok {
			out = append(out, c)
		}
	}
	return out
}

// SessionPortReads da las lecturas que faltan para ubicar el puerto de la sesión, dado lo ya leído (nil si no faltan o no hay origen IPv4).
// El servicio las pide en rondas hasta que no queden.
func SessionPortReads(outs map[string]string) []string {
	cmds, _ := sessionStep(outs)
	return cmds
}

// sessionPorts da el puerto de la sesión con lo leído hasta ahora; sin certeza known es false y la plantilla decide con el modo del puerto.
func sessionPorts(outs map[string]string) sessionPort {
	if cmds, sp := sessionStep(outs); len(cmds) == 0 {
		return sp
	}
	return sessionPort{}
}

func sessionStep(outs map[string]string) (cmds []string, sp sessionPort) {
	origin, ok := sessionOrigin(outs[showUsersCmd])
	if !ok || !origin.Is4() { // shortcut: solo IPv4, con IPv6 no se identifica y se aplica la regla de trunk/canal; ampliar si hace falta
		return nil, sp
	}
	arpO, route := "show ip arp "+origin.String(), "show ip route "+origin.String()
	if c := unread(outs, arpO, route); c != nil {
		return c, sp
	}
	hop := origin
	if _, ok := arpRow(outs[arpO], origin); !ok {
		if hop, ok = nextHopOf(outs[route]); !ok {
			return nil, sp
		}
	}
	arpH := "show ip arp " + hop.String()
	if c := unread(outs, arpH); c != nil {
		return c, sp
	}
	row, ok := arpRow(outs[arpH], hop)
	if !ok {
		return nil, sp
	}
	sp.mac = row.MAC
	port := row.Iface
	if v, isSVI := strings.CutPrefix(strings.ToLower(row.Iface), "vlan"); isSVI {
		sp.vlan = v
		cam := "show mac address-table address " + row.MAC
		if c := unread(outs, cam); c != nil {
			return c, sp
		}
		ents, _ := iosxe.ParseMACTable(outs[cam])
		var seen []string
		for _, e := range ents {
			if e.MAC == row.MAC && !strings.EqualFold(e.Port, "CPU") && (e.VLAN == v || e.VLAN == "All") && !slices.Contains(seen, e.Port) {
				seen = append(seen, e.Port)
			}
		}
		if len(seen) != 1 { // sin entrada o aprendida en varios puertos: no hay certeza
			return nil, sp
		}
		port = seen[0]
	}
	// Solo una interfaz física o un canal identifica el puerto: BDI, túneles o «Drop»/«Router» de la tabla MAC no se pueden proteger.
	if !ValidTrunkInterface(iosxe.ShortIf(strings.SplitN(port, ".", 2)[0])) && !ValidTrunkInterface(strings.SplitN(port, ".", 2)[0]) {
		return nil, sp
	}
	sp.ports = map[string]bool{}
	for _, p := range []string{port, strings.SplitN(port, ".", 2)[0]} { // una subinterfaz protege también a su puerto
		sp.ports[strings.ToLower(iosxe.ShortIf(p))] = true
	}
	if base := strings.SplitN(port, ".", 2)[0]; strings.HasPrefix(strings.ToLower(base), "po") {
		if c := unread(outs, showEtherchannelCmd); c != nil {
			return c, sp
		}
		chans, _ := iosxe.ParseEtherChannels(outs[showEtherchannelCmd])
		for _, ch := range chans {
			if strings.EqualFold(ch.Name, base) {
				for _, m := range ch.Members {
					sp.ports[strings.ToLower(m.Port)] = true
				}
			}
		}
	}
	sp.known = true
	return nil, sp
}

func (sp sessionPort) isSession(name string) bool {
	return sp.known && sp.ports[strings.ToLower(iosxe.ShortIf(name))]
}

// check decide para un cambio que puede cortar el acceso por el puerto name: si es el puerto de la sesión, o si no se pudo identificar y es un
// trunk o canal (uplink), da el rechazo; si no se pudo identificar y es de acceso, lo acepta con una nota.
func (sp sessionPort) check(name string, uplink bool) (refusal, warn i18n.Text) {
	switch {
	case sp.isSession(name):
		return i18n.Tx("assist.refused.puerto_de_la_sesion", "port", name, "mac", sp.mac), i18n.Text{}
	case sp.known:
		return i18n.Text{}, i18n.Text{}
	case uplink:
		return i18n.Tx("assist.refused.puerto_de_la_sesion_dudoso", "port", name), i18n.Text{}
	}
	return i18n.Text{}, note("assist.note.puerto_de_la_sesion_dudoso", "port", name)
}

// checkTrunkRemove es check para quitar la VLAN vlan de un trunk: solo corta si es la que lleva la sesión (o no se sabe cuál es).
func (sp sessionPort) checkTrunkRemove(name string, vlan int) i18n.Text {
	carries := sp.vlan == "" || sp.vlan == ntoa(vlan)
	switch {
	case sp.isSession(name) && carries:
		return i18n.Tx("assist.refused.vlan_de_la_sesion", "port", name, "vlan", vlan, "mac", sp.mac)
	case !sp.known && carries:
		return i18n.Tx("assist.refused.puerto_de_la_sesion_dudoso", "port", name)
	}
	return i18n.Text{}
}

// uplinkOf dice si el puerto capturado es candidato a uplink: trunk (configurado, administrativo u operativo), ruteado o Port-channel.
func uplinkOf(p l2Port) bool {
	oper, _ := iosxe.ParseSwitchportOperMode(p.switchport)
	admin, _ := iosxe.ParseSwitchportMode(p.switchport)
	return p.cur.Trunk || p.cur.Routed || p.cur.L3 || oper == "trunk" || admin == "trunk" || poRe.MatchString(p.name)
}

func addNote(dp *DevicePlan, t i18n.Text) {
	dp.NoteItems = append(dp.NoteItems, t)
	dp.Notes = append(dp.Notes, t.In(i18n.Es))
}
