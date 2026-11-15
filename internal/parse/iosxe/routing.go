package iosxe

// Protocolos de enrutamiento y árbol de expansión: OSPF, BGP, HSRP, STP y el
// resumen de rutas. Mismo criterio que el resto del paquete: formato inesperado
// devuelve ok=false, nunca cero filas en silencio.

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

func blank(text string) bool { return strings.TrimSpace(text) == "" }

// ---- duraciones de IOS ----

var iosDurRe = regexp.MustCompile(`^(?:(\d+)y)?(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?$`)

// IOSDuration entiende "00:01:10", "3d04h", "1w2d", "1y2w"; "never" no es duración.
func IOSDuration(s string) (time.Duration, bool) {
	if p := strings.Split(s, ":"); len(p) == 3 {
		h, e1 := strconv.Atoi(p[0])
		m, e2 := strconv.Atoi(p[1])
		sec, e3 := strconv.Atoi(p[2])
		if e1 != nil || e2 != nil || e3 != nil {
			return 0, false
		}
		return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(sec)*time.Second, true
	}
	m := iosDurRe.FindStringSubmatch(s)
	if m == nil || s == "" {
		return 0, false
	}
	var d time.Duration
	for i, u := range []time.Duration{365 * 24 * time.Hour, 7 * 24 * time.Hour, 24 * time.Hour, time.Hour} {
		if m[i+1] != "" {
			n, _ := strconv.Atoi(m[i+1])
			d += time.Duration(n) * u
		}
	}
	return d, true
}

// ---- show spanning-tree detail ----

type STPInstance struct {
	Name     string
	Changes  int64
	Since    time.Duration
	SinceOK  bool
	Lines    []string
	From     string
	fromNext bool
}

var (
	stpInstRe   = regexp.MustCompile(`^\s*((?:VLAN|MST)\d+) is executing`)
	stpChangeRe = regexp.MustCompile(`Number of topology changes (\d+) last change occurred (\S+) ago`)
	stpFromRe   = regexp.MustCompile(`^\s+from (\S+)\s*$`)
)

func ParseSTPDetail(text string) ([]STPInstance, bool) {
	if strings.Contains(text, "No spanning tree instance") {
		return nil, true
	}
	var out []STPInstance
	name := ""
	for _, ln := range lines(text) {
		if m := stpInstRe.FindStringSubmatch(ln); m != nil {
			name = m[1]
			continue
		}
		if m := stpChangeRe.FindStringSubmatch(ln); m != nil {
			d, ok := IOSDuration(m[2])
			out = append(out, STPInstance{Name: name, Changes: atoi(m[1]), Since: d, SinceOK: ok, Lines: []string{ln}, fromNext: true})
			continue
		}
		if n := len(out); n > 0 && out[n-1].fromNext {
			if m := stpFromRe.FindStringSubmatch(ln); m != nil {
				out[n-1].From = m[1]
				out[n-1].Lines = append(out[n-1].Lines, ln)
			}
			out[n-1].fromNext = false
		}
	}
	return out, len(out) > 0
}

// ---- show spanning-tree root ----

// STPRoot es la raíz de una VLAN: prioridad y MAC del puente raíz y, si no es este equipo, el puerto hacia él.
type STPRoot struct{ VLAN, Priority, MAC, Port string }

func ParseSTPRootTable(text string) ([]STPRoot, bool) {
	var out []STPRoot
	for _, ln := range lines(text) {
		f := strings.Fields(ln)
		if len(f) >= 7 && strings.HasPrefix(f[0], "VLAN") && numRe.MatchString(f[1]) {
			r := STPRoot{VLAN: f[0], Priority: f[1], MAC: f[2]}
			if len(f) >= 8 {
				r.Port = f[7]
			}
			out = append(out, r)
		}
	}
	return out, len(out) > 0
}

var numRe = regexp.MustCompile(`^\d+$`)

// ---- show ip bgp summary ----

type BGPNeighbor struct {
	ID, AS, UpDown, State string
	Prefixes              int
	Established           bool
	Lines                 []string // una, o dos si IOS partió la fila
}

var (
	bgpHeaderRe   = regexp.MustCompile(`^Neighbor\s+V\s+AS\s+MsgRcvd`)
	bgpRowRe      = regexp.MustCompile(`^(\S+)\s+(\d)\s+(\d+(?:\.\d+)?)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\S+)\s+(.+?)\s*$`)
	bgpAddrOnlyRe = regexp.MustCompile(`^\S+$`)
)

// ParseBGP une la fila que IOS parte cuando la dirección (IPv6 larga) no cabe:
// la dirección sola en una línea y los contadores en la siguiente.
func ParseBGP(text string) ([]BGPNeighbor, bool) {
	if blank(text) || strings.Contains(text, "BGP not active") {
		return nil, true
	}
	var out []BGPNeighbor
	header := false
	pending := ""
	for _, ln := range lines(text) {
		if bgpHeaderRe.MatchString(ln) {
			header = true
			continue
		}
		if !header {
			continue
		}
		if bgpAddrOnlyRe.MatchString(ln) {
			pending = ln
			continue
		}
		row, raw := ln, []string{ln}
		if pending != "" {
			row, raw = pending+" "+strings.TrimSpace(ln), []string{pending, ln}
			pending = ""
		}
		if m := bgpRowRe.FindStringSubmatch(row); m != nil {
			n := BGPNeighbor{ID: m[1], AS: m[3], UpDown: m[4], State: m[5], Lines: raw}
			if p, err := strconv.Atoi(m[5]); err == nil {
				n.Prefixes, n.Established, n.State = p, true, "Established"
			}
			out = append(out, n)
		}
	}
	return out, header
}

// ---- show ip ospf neighbor ----

type OSPFNeighbor struct {
	ID, State, Role, Address, Interface string
	Line                                string
}

var (
	ospfHeaderRe = regexp.MustCompile(`^Neighbor ID\s+Pri\s+State`)
	ospfRowRe    = regexp.MustCompile(`^(\S+)\s+\d+\s+([A-Z0-9]+)/\s*(\S+)\s+\S+\s+(\S+)\s+(\S+)\s*$`)
)

func ParseOSPF(text string) ([]OSPFNeighbor, bool) {
	if blank(text) {
		return nil, true
	}
	var out []OSPFNeighbor
	header := false
	for _, ln := range lines(text) {
		if ospfHeaderRe.MatchString(ln) {
			header = true
			continue
		}
		if m := ospfRowRe.FindStringSubmatch(ln); header && m != nil {
			out = append(out, OSPFNeighbor{ID: m[1], State: m[2], Role: m[3], Address: m[4], Interface: m[5], Line: ln})
		}
	}
	return out, header
}

// ---- show standby brief ----

type HSRPGroup struct {
	Interface, Group, State, Active, Standby, VIP string
	Line                                          string
}

var (
	hsrpHeaderRe = regexp.MustCompile(`^Interface\s+Grp\s+Pri\s+P\s+State`)
	hsrpRowRe    = regexp.MustCompile(`^(\S+)\s+(\d+)\s+\d+\s+(?:P\s+)?(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$`)
)

func ParseHSRP(text string) ([]HSRPGroup, bool) {
	if blank(text) {
		return nil, true
	}
	var out []HSRPGroup
	header := false
	for _, ln := range lines(text) {
		if hsrpHeaderRe.MatchString(ln) {
			header = true
			continue
		}
		if m := hsrpRowRe.FindStringSubmatch(ln); header && m != nil {
			out = append(out, HSRPGroup{Interface: m[1], Group: m[2], State: m[3], Active: m[4], Standby: m[5], VIP: m[6], Line: ln})
		}
	}
	return out, header
}

// ---- show ip eigrp neighbors ----

type EIGRPNeighbor struct {
	Address, Interface, AS string
	Line                   string
}

var (
	eigrpASRe     = regexp.MustCompile(`^EIGRP-IPv[46] .*Neighbors for AS\((\d+)\)`)
	eigrpHeaderRe = regexp.MustCompile(`^H\s+Address\s+Interface`)
	eigrpRowRe    = regexp.MustCompile(`^\d+\s+(\S+)\s+(\S+)\s+\d+\s+\S+\s+\d+\s+\d+\s+\d+\s+\d+\s*$`)
)

// ParseEIGRP lee el formato clásico y el nombrado. shortcut: el vecino IPv6 (dirección en la línea siguiente)
// no se lee; llegar a él cuando haya una salida de EIGRP para IPv6.
func ParseEIGRP(text string) ([]EIGRPNeighbor, bool) {
	if blank(text) {
		return nil, true
	}
	var out []EIGRPNeighbor
	header, as := false, ""
	for _, ln := range lines(text) {
		if m := eigrpASRe.FindStringSubmatch(ln); m != nil {
			as = m[1]
		} else if eigrpHeaderRe.MatchString(ln) {
			header = true
		} else if m := eigrpRowRe.FindStringSubmatch(ln); header && m != nil {
			out = append(out, EIGRPNeighbor{Address: m[1], Interface: ShortIf(m[2]), AS: as, Line: ln})
		}
	}
	return out, header
}

// ---- show mpls ldp neighbor ----

type LDPNeighbor struct {
	PeerID, State string
	Line          string // la línea «Peer LDP Ident»
}

var (
	ldpPeerRe  = regexp.MustCompile(`^\s*Peer LDP Ident: (\S+?);`)
	ldpStateRe = regexp.MustCompile(`^\s*State: (\w+)`)
)

func ParseLDPNeighbors(text string) ([]LDPNeighbor, bool) {
	if blank(text) {
		return nil, true
	}
	var out []LDPNeighbor
	for _, ln := range lines(text) {
		if m := ldpPeerRe.FindStringSubmatch(ln); m != nil {
			out = append(out, LDPNeighbor{PeerID: m[1], Line: ln})
		} else if m := ldpStateRe.FindStringSubmatch(ln); m != nil && len(out) > 0 {
			out[len(out)-1].State = m[1]
		}
	}
	return out, len(out) > 0
}

// ---- show track brief ----

type TrackObject struct {
	ID, Type, Instance, Parameter, State string
	Line                                 string
}

var (
	trackHeaderRe = regexp.MustCompile(`^Track\s+Type\s+Instance\s+Parameter\s+State`)
	// el tipo puede ser de dos palabras (ip sla, ip route) separadas por un solo espacio
	trackRowRe = regexp.MustCompile(`^(\d+)\s+(\S+(?: \S+)?)\s+(\S+)\s+(\S+)\s+(Up|Down)\s+\S+\s*$`)
)

func ParseTrack(text string) ([]TrackObject, bool) {
	if blank(text) {
		return nil, true
	}
	var out []TrackObject
	header := false
	for _, ln := range lines(text) {
		if trackHeaderRe.MatchString(ln) {
			header = true
			continue
		}
		if m := trackRowRe.FindStringSubmatch(ln); header && m != nil {
			out = append(out, TrackObject{ID: m[1], Type: m[2], Instance: m[3], Parameter: m[4], State: m[5], Line: ln})
		}
	}
	return out, header
}

// ---- show glbp brief ----

var (
	glbpHeaderRe = regexp.MustCompile(`^Interface\s+Grp\s+Fwd\s+Pri\s+State`)
	glbpRowRe    = regexp.MustCompile(`^(\S+)\s+(\d+)\s+(-|\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*$`)
)

// ParseGLBP reutiliza HSRPGroup. Group es «50» para el AVG y «50/1» para el AVF 1, para que la clave sea única;
// VIP es la IP virtual (AVG) o la MAC virtual (AVF).
func ParseGLBP(text string) ([]HSRPGroup, bool) {
	if blank(text) {
		return nil, true
	}
	var out []HSRPGroup
	header := false
	for _, ln := range lines(text) {
		if glbpHeaderRe.MatchString(ln) {
			header = true
			continue
		}
		if m := glbpRowRe.FindStringSubmatch(ln); header && m != nil {
			grp := m[2]
			if m[3] != "-" {
				grp += "/" + m[3]
			}
			out = append(out, HSRPGroup{Interface: m[1], Group: grp, State: m[5], VIP: m[6], Active: m[7], Standby: m[8], Line: ln})
		}
	}
	return out, header
}

// ---- show vrrp brief ----

var (
	vrrpHeaderRe = regexp.MustCompile(`^Interface\s+Grp\s+Pri\s+Time`)
	vrrpRowRe    = regexp.MustCompile(`^(\S+)\s+(\d+)\s+\d+\s+\d+\s+(?:Y\s+)?(?:Y\s+)?(\S+)\s+(\S+)\s+(\S+)\s*$`)
)

// ParseVRRP reutiliza HSRPGroup: State es el estado y Active la dirección del master.
func ParseVRRP(text string) ([]HSRPGroup, bool) {
	if blank(text) {
		return nil, true
	}
	var out []HSRPGroup
	header := false
	for _, ln := range lines(text) {
		if vrrpHeaderRe.MatchString(ln) {
			header = true
			continue
		}
		if m := vrrpRowRe.FindStringSubmatch(ln); header && m != nil {
			out = append(out, HSRPGroup{Interface: m[1], Group: m[2], State: m[3], Active: m[4], VIP: m[5], Line: ln})
		}
	}
	return out, header
}

// ---- show ip route summary ----

// RouteSummary es una fila por origen ("ospf 1", "bgp 65001", "connected").
type RouteSummary struct {
	Source            string
	Networks, Subnets int
}

func ParseRouteSummary(text string) ([]RouteSummary, bool) {
	var out []RouteSummary
	for _, ln := range lines(text) {
		f := strings.Fields(ln)
		if len(f) < 6 || f[0] == "Total" || f[0] == "Route" {
			continue
		}
		nums := f[len(f)-5:]
		ok := true
		for _, n := range nums {
			ok = ok && numRe.MatchString(n)
		}
		if ok {
			out = append(out, RouteSummary{Source: strings.Join(f[:len(f)-5], " "), Networks: int(atoi(nums[0])), Subnets: int(atoi(nums[1]))})
		}
	}
	return out, len(out) > 0
}
