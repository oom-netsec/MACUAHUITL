package change

import (
	"regexp"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Comandos del playbook ios-xe/pre-post por faceta. Una faceta solo se compara si
// ambas capturas tienen su salida.
var facetCmd = map[string]string{
	"versión":    "show version",
	"config":     "show running-config",
	"interfaces": "show ip interface brief",
	"cdp":        "show cdp neighbors detail",
	"lldp":       "show lldp neighbors detail",
	"ospf":       "show ip ospf neighbor",
	"bgp":        "show ip bgp summary",
	"rutas":      "show ip route summary",
	"mac":        "show mac address-table",
	"arp":        "show ip arp",
	"hsrp":       "show standby brief",
	"stp":        "show spanning-tree root",
}

// Snapshot es el estado de un equipo extraído de sus salidas.
type Snapshot struct {
	Version       string
	UptimeMinutes int               // -1 = no se pudo leer
	Interfaces    map[string]string // interfaz → "estado/protocolo"
	CDP, LLDP     map[string]string // "vecino @ interfaz local" → puerto remoto
	OSPF          map[string]string // "router-id @ interfaz" → estado (FULL, 2WAY, INIT…)
	BGP           map[string]string // vecino → Established o el estado
	BGPPfx        map[string]int
	Routes        map[string]int       // origen ("ospf 1") → redes + subredes
	MACs          map[string]int       // VLAN → MACs
	ARP           map[string]int       // interfaz → entradas
	HSRP          map[string]string    // "Vl10 grupo 10" → estado (la clave es interna; se muestra HSRPLabel)
	HSRPLabel     map[string]i18n.Text // clave → «Vl10 grupo 10» en el idioma pedido
	STPRoot       map[string]string    // VLAN → "prioridad MAC" de la raíz
	STPPort       map[string]string    // VLAN → puerto raíz
	Config        *iosconf.Node
	Have          map[string]bool // facetas con salida
}

// Parse arma el Snapshot con los parsers de internal/parse/iosxe. Una faceta cuya
// salida no se reconoce queda vacía, igual que si no tuviera líneas útiles.
func Parse(outputs map[string]string) Snapshot {
	s := Snapshot{UptimeMinutes: -1, Have: map[string]bool{}, Interfaces: map[string]string{}, CDP: map[string]string{}, LLDP: map[string]string{},
		OSPF: map[string]string{}, BGP: map[string]string{}, BGPPfx: map[string]int{}, Routes: map[string]int{}, MACs: map[string]int{},
		ARP: map[string]int{}, HSRP: map[string]string{}, HSRPLabel: map[string]i18n.Text{}, STPRoot: map[string]string{}, STPPort: map[string]string{}}
	out := map[string]string{}
	for f, cmd := range facetCmd {
		if v, c := capture.Get(outputs, cmd); c != "" {
			out[f], s.Have[f] = v, true
		}
	}
	v, _ := iosxe.ParseVersion(out["versión"])
	s.Version = v.Version
	if v.UptimeLine != "" {
		s.UptimeMinutes = int(v.Uptime / time.Minute)
	}
	if s.Have["config"] {
		s.Config = iosconf.Parse(out["config"])
	}
	brief, _ := iosxe.ParseIPBrief(out["interfaces"])
	for _, r := range brief {
		s.Interfaces[r.Raw] = r.Status + "/" + r.Protocol
	}
	cdp, _ := iosxe.ParseCDP(out["cdp"])
	lldp, _ := iosxe.ParseLLDP(out["lldp"])
	for _, n := range cdp {
		if n.LocalRaw != "" {
			s.CDP[n.Device+" @ "+n.LocalRaw] = n.RemoteRaw
		}
	}
	for _, n := range lldp {
		if n.LocalRaw != "" {
			s.LLDP[n.Device+" @ "+n.LocalRaw] = n.RemoteRaw
		}
	}
	ospf, _ := iosxe.ParseOSPF(out["ospf"])
	for _, n := range ospf {
		s.OSPF[n.ID+" @ "+n.Interface] = n.State
	}
	bgp, _ := iosxe.ParseBGP(out["bgp"])
	for _, n := range bgp {
		s.BGP[n.ID] = n.State
		if n.Established {
			s.BGPPfx[n.ID] = n.Prefixes
		}
	}
	routes, _ := iosxe.ParseRouteSummary(out["rutas"])
	for _, r := range routes {
		s.Routes[r.Source] = r.Networks + r.Subnets
	}
	macs, _ := iosxe.ParseMACTable(out["mac"])
	for _, m := range macs {
		if numRe.MatchString(m.VLAN) { // "All" son entradas del propio equipo
			s.MACs[m.VLAN]++
		}
	}
	arp, _ := iosxe.ParseARP(out["arp"])
	for _, a := range arp {
		s.ARP[a.Iface]++
	}
	hsrp, _ := iosxe.ParseHSRP(out["hsrp"])
	for _, g := range hsrp {
		s.HSRP[hsrpKey(g)], s.HSRPLabel[hsrpKey(g)] = g.State, i18n.Tx("change.key.hsrp", "iface", g.Interface, "group", g.Group)
	}
	stp, _ := iosxe.ParseSTPRootTable(out["stp"])
	for _, r := range stp {
		s.STPRoot[r.VLAN] = r.Priority + " " + r.MAC
		if r.Port != "" {
			s.STPPort[r.VLAN] = r.Port
		}
	}
	return s
}

var numRe = regexp.MustCompile(`^\d+$`)

func hsrpKey(g iosxe.HSRPGroup) string {
	return i18n.Tx("change.key.hsrp", "iface", g.Interface, "group", g.Group).In(i18n.Es)
}
