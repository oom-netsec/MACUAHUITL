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
