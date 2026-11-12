package iosxe

import (
	"net/netip"
	"strconv"
	"strings"
)

// Parsers del lote L3 y gestión de la fase 28d: rutas estáticas, NTP, logging, SNMP, banner, líneas vty, ACL estándar y
// ip helper-address. Cada uno lee la salida de un `show running-config | include/section ...` (o show snmp user / show ip access-lists)
// y devuelve ok=false si la salida trae un aviso de error de IOS o una línea de su familia que no entiende: quien planea lo toma por
// «no se pudo leer» y rechaza. Formatos de la documentación de Cisco; sin validar en laboratorio.

// readFailed dice si la salida es un aviso de error de IOS en vez de la lectura pedida.
func readFailed(text string) bool {
	for _, raw := range lines(text) {
		l := strings.TrimSpace(raw)
		if strings.HasPrefix(l, "%") || strings.Contains(l, "Invalid input") || strings.Contains(l, "Incomplete command") {
			return true
		}
	}
	return false
}

// cfgFields devuelve, por cada línea útil de la salida, sus palabras (sin comentarios, líneas en blanco ni el encabezado del running).
func cfgFields(text string) [][]string {
	var out [][]string
	for _, raw := range lines(text) {
		l := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if l == "" || strings.HasPrefix(l, "!") || strings.HasPrefix(l, "Building") || strings.HasPrefix(l, "Current") || l == "end" {
			continue
		}
		out = append(out, strings.Fields(l))
	}
	return out
}

func isIPv4(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

// ---- rutas estáticas ----

// StaticRoute es una línea `ip route` de la tabla global (las de VRF no se leen: son otra tabla).
type StaticRoute struct {
	Net, Mask, Iface, NextHop, Distance, Name string
	Other                                     []string // lo que sigue y no se entiende (tag, track, permanent...)
}

// ParseStaticRoutes lee `show running-config | include ^ip route`.
func ParseStaticRoutes(text string) ([]StaticRoute, bool) {
	var out []StaticRoute
	for _, f := range cfgFields(text) {
		if len(f) < 2 || f[0] != "ip" || f[1] != "route" {
			return nil, false
		}
		if len(f) > 2 && f[2] == "vrf" {
			continue
		}
		if len(f) < 4 || !isIPv4(f[2]) || !isIPv4(f[3]) {
			return nil, false
		}
		r := StaticRoute{Net: f[2], Mask: f[3]}
		rest := f[4:]
		if len(rest) > 0 && !isIPv4(rest[0]) && !digits(rest[0]) {
			r.Iface, rest = rest[0], rest[1:]
		}
		if len(rest) > 0 && isIPv4(rest[0]) {
			r.NextHop, rest = rest[0], rest[1:]
		}
		if r.Iface == "" && r.NextHop == "" {
			return nil, false
		}
		if len(rest) > 0 && digits(rest[0]) {
			r.Distance, rest = rest[0], rest[1:]
		}
		for i := 0; i < len(rest); i++ {
			if rest[i] == "name" && i+1 < len(rest) {
				r.Name = rest[i+1]
				i++
				continue
			}
			r.Other = append(r.Other, rest[i])
		}
		out = append(out, r)
	}
	if len(out) == 0 && readFailed(text) {
		return nil, false
	}
	return out, true
}

// ---- NTP ----

// NTPServer es una línea `ntp server`: Options es todo lo que sigue a la dirección (prefer, key, version, source...).
type NTPServer struct {
	Addr, Vrf string
	Options   []string
}

// ParseNTPServers lee `show running-config | include ^ntp`; las demás líneas de ntp (peer, authentication-key...) no cuentan.
func ParseNTPServers(text string) ([]NTPServer, bool) {
	var out []NTPServer
	for _, f := range cfgFields(text) {
		if len(f) < 3 || f[0] != "ntp" || f[1] != "server" {
			continue
		}
		s, rest := NTPServer{}, f[2:]
		if rest[0] == "vrf" && len(rest) >= 3 {
			s.Vrf, rest = rest[1], rest[2:]
		}
		if rest[0] == "ip" && len(rest) >= 2 {
			rest = rest[1:]
		}
		s.Addr, s.Options = rest[0], rest[1:]
		out = append(out, s)
	}
	if len(out) == 0 && readFailed(text) {
		return nil, false
	}
	return out, true
}

// ---- logging ----

// LogHost es un destino de syslog; IOS 12.x lo escribe `logging IP` y 15.x/XE `logging host IP`.
type LogHost struct {
	Addr    string
	Options []string
}

// Transport da el transporte y el puerto con que el destino manda syslog. ok=false si trae algo más que `transport udp|tcp [port N]`.
// IOS puede omitir `port 514` (udp) o todo el sufijo en el running; sin puerto vale el de fábrica: udp 514 y tcp 601 (supuesto sin
// validar en laboratorio).
func (h LogHost) Transport() (string, int, bool) {
	o := h.Options
	if len(o) == 0 {
		return "udp", 514, true
	}
	if len(o) != 2 && len(o) != 4 || o[0] != "transport" || o[1] != "udp" && o[1] != "tcp" {
		return "", 0, false
	}
	port := 514
	if o[1] == "tcp" {
		port = 601
	}
	if len(o) == 4 {
		n, err := strconv.Atoi(o[3])
		if o[2] != "port" || err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != o[3] {
			return "", 0, false
		}
		port = n
	}
	return o[1], port, true
}

// LoggingCfg es lo que importa de `show running-config | include ^logging`: los destinos y el nivel de trap tal como lo escribe el
// running (vacío = sin la línea, el nivel de fábrica).
type LoggingCfg struct {
	Hosts []LogHost
	Trap  string
	// NoTrap: el running trae `no logging trap` (varias versiones lo dejan al escribirlo): el syslog está apagado, que no es el nivel de fábrica.
	NoTrap bool
}

func ParseLoggingCfg(text string) (LoggingCfg, bool) {
	var c LoggingCfg
	for _, f := range cfgFields(text) {
		switch {
		case len(f) >= 3 && f[0] == "no" && f[1] == "logging" && f[2] == "trap":
			c.NoTrap = true
		case len(f) < 2 || f[0] != "logging":
		case f[1] == "host" && len(f) >= 3:
			c.Hosts = append(c.Hosts, LogHost{Addr: f[2], Options: f[3:]})
		case f[1] == "trap" && len(f) >= 3:
			c.Trap = strings.ToLower(f[2])
		case isIPv4(f[1]):
			c.Hosts = append(c.Hosts, LogHost{Addr: f[1], Options: f[2:]})
		}
	}
	if len(c.Hosts) == 0 && c.Trap == "" && !c.NoTrap && readFailed(text) {
		return LoggingCfg{}, false
	}
	return c, true
}

// ---- SNMP ----

// SNMPCommunity es una línea `snmp-server community`. Perm vacío = no se entendió el permiso.
type SNMPCommunity struct {
	Name, Perm, ACL string
	Other           []string
}

func ParseSNMPCommunities(text string) ([]SNMPCommunity, bool) {
	var out []SNMPCommunity
	for _, f := range cfgFields(text) {
		if len(f) < 3 || f[0] != "snmp-server" || f[1] != "community" {
			continue
		}
		c := SNMPCommunity{Name: f[2]}
		for i := 3; i < len(f); i++ {
			switch w := strings.ToLower(f[i]); {
			case (w == "view" || w == "ipv6") && i+1 < len(f):
				c.Other = append(c.Other, f[i], f[i+1])
				i++
			case w == "ro" || w == "rw":
				c.Perm = strings.ToUpper(w)
			case c.ACL == "":
				c.ACL = f[i]
			default:
				c.Other = append(c.Other, f[i])
			}
		}
		out = append(out, c)
	}
	if len(out) == 0 && readFailed(text) {
		return nil, false
	}
	return out, true
}

// SNMPGroup es una línea `snmp-server group`; Level es auth, noauth o priv en v3 (vacío en v1/v2c).
type SNMPGroup struct {
	Name, Version, Level string
	Other                []string
}

func ParseSNMPGroups(text string) ([]SNMPGroup, bool) {
	var out []SNMPGroup
	for _, f := range cfgFields(text) {
		if len(f) < 4 || f[0] != "snmp-server" || f[1] != "group" {
			continue
		}
		g := SNMPGroup{Name: f[2], Version: strings.ToLower(f[3]), Other: f[4:]}
		if g.Version == "v3" && len(f) > 4 && (f[4] == "auth" || f[4] == "noauth" || f[4] == "priv") {
			g.Level, g.Other = f[4], f[5:]
		}
		out = append(out, g)
	}
	if len(out) == 0 && readFailed(text) {
		return nil, false
	}
	return out, true
}

// SNMPUser es un usuario SNMPv3 de `show snmp user` (IOS no los muestra en el running-config).
type SNMPUser struct{ Name, EngineID, Auth, Priv, Group string }

// ParseSNMPUsers lee `show snmp user`: sin usuarios IOS no imprime nada. El aviso «%SNMP agent not enabled» es ok=false: sin saber qué
// verá el equipo al activar el agente, no hay línea base fiable.
func ParseSNMPUsers(text string) ([]SNMPUser, bool) {
	if readFailed(text) {
		return nil, false
	}
	var out []SNMPUser
	for _, raw := range lines(text) {
		k, v, found := strings.Cut(strings.TrimSpace(raw), ":")
		if !found {
			continue
		}
		v = strings.TrimSpace(v)
		if k == "User name" {
			out = append(out, SNMPUser{Name: v})
			continue
		}
		if len(out) == 0 {
			continue
		}
		u := &out[len(out)-1]
		switch k {
		case "Engine ID":
			u.EngineID = v
		case "Authentication Protocol":
			u.Auth = v
		case "Privacy Protocol":
			u.Priv = v
		case "Group-name":
			u.Group = v
		}
	}
	return out, true
}

// ---- banner ----

// Banner es el banner motd: Multi = ocupa varias líneas (la reversa de una línea no lo restauraría).
type Banner struct {
	Present, Multi bool
	Text           string // solo el de una línea
}

// ParseBannerMOTD lee `show running-config | section banner motd`; IOS muestra el delimitador como ^C.
func ParseBannerMOTD(text string) (Banner, bool) {
	for _, raw := range lines(text) {
		rest, found := strings.CutPrefix(strings.TrimSpace(raw), "banner motd ")
		if !found {
			continue
		}
		if len(rest) >= 5 && strings.HasPrefix(rest, "^C") && strings.HasSuffix(rest, "^C") {
			return Banner{Present: true, Text: rest[2 : len(rest)-2]}, true
		}
		return Banner{Present: true, Multi: true}, true
	}
	return Banner{}, !readFailed(text)
}

// ---- líneas vty ----

// VtyBlock es un bloque `line vty Lo Hi` del running-config con su `access-class ... in` si lo tiene.
type VtyBlock struct {
	Lo, Hi      int
	AccessIn    string
	HasAccessIn bool
	Lines       []string // las líneas del bloque, sin sangría
}

// ParseVtyBlocks lee `show running-config | section ^line vty`.
func ParseVtyBlocks(text string) ([]VtyBlock, bool) {
	var out []VtyBlock
	cur := -1
	for _, raw := range lines(text) {
		raw = strings.TrimRight(raw, "\r")
		l := strings.TrimSpace(raw)
		if l == "" || strings.HasPrefix(l, "!") || l == "end" {
			continue
		}
		f := strings.Fields(l)
		if raw[0] != ' ' && raw[0] != '\t' {
			cur = -1
			if len(f) >= 3 && f[0] == "line" && f[1] == "vty" {
				lo, err := strconv.Atoi(f[2])
				hi := lo
				if err == nil && len(f) >= 4 {
					hi, err = strconv.Atoi(f[3])
				}
				if err != nil {
					return nil, false
				}
				out = append(out, VtyBlock{Lo: lo, Hi: hi})
				cur = len(out) - 1
			}
			continue
		}
		if cur < 0 {
			continue
		}
		b := &out[cur]
		b.Lines = append(b.Lines, l)
		if len(f) >= 3 && f[0] == "access-class" && f[2] == "in" && !b.HasAccessIn {
			b.HasAccessIn, b.AccessIn = true, f[1]
		}
	}
	if len(out) == 0 && readFailed(text) {
		return nil, false
	}
	return out, true
}

// ---- ACL estándar ----

// ACLEntry es una regla de una ACL estándar: coincide con las direcciones que difieren de Net solo en los bits en 1 de Wild.
type ACLEntry struct {
	Action    string // permit o deny
	Net, Wild netip.Addr
}

// Matches dice si ip cae en la regla.
func (e ACLEntry) Matches(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	a, n, w := ip.As4(), e.Net.As4(), e.Wild.As4()
	for i := range a {
		if (a[i]^n[i])&^w[i] != 0 {
			return false
		}
	}
	return true
}

// AccessList es una ACL de `show ip access-lists`. De las extendidas solo se sabe que lo son: no se leen sus reglas.
type AccessList struct {
	Name     string
	Standard bool
	Entries  []ACLEntry
}

// ParseAccessLists lee `show ip access-lists [NOMBRE]`. Sin ACL IOS no imprime nada.
func ParseAccessLists(text string) ([]AccessList, bool) {
	var out []AccessList
	for _, f := range cfgFields(text) {
		if len(f) >= 5 && f[2] == "access" && f[3] == "list" && f[1] == "IP" && (f[0] == "Standard" || f[0] == "Extended") {
			out = append(out, AccessList{Name: f[4], Standard: f[0] == "Standard"})
			continue
		}
		if len(out) == 0 {
			return nil, false
		}
		cur := &out[len(out)-1]
		if !cur.Standard {
			continue
		}
		e, remark, ok := parseStdEntry(f)
		if !ok {
			return nil, false
		}
		if !remark {
			cur.Entries = append(cur.Entries, e)
		}
	}
	return out, true
}

// parseStdEntry lee `[SEQ] permit|deny ORIGEN [log] [(N matches)]`; remark=true para un comentario.
func parseStdEntry(f []string) (e ACLEntry, remark, ok bool) {
	if len(f) > 0 && digits(f[0]) {
		f = f[1:]
	}
	if len(f) > 0 && f[0] == "remark" {
		return e, true, true
	}
	if len(f) < 2 || (f[0] != "permit" && f[0] != "deny") {
		return e, false, false
	}
	e.Action = f[0]
	var spec []string
	for _, t := range f[1:] {
		if strings.HasPrefix(t, "(") { // «(12 matches)»: el contador cierra la línea
			break
		}
		if t = strings.TrimSuffix(t, ","); t != "log" && t != "log-input" && t != "wildcard" && t != "bits" {
			spec = append(spec, t)
		}
	}
	any4, zero := netip.AddrFrom4([4]byte{}), netip.AddrFrom4([4]byte{})
	switch {
	case len(spec) == 1 && spec[0] == "any":
		e.Net, e.Wild = any4, netip.AddrFrom4([4]byte{255, 255, 255, 255})
	case len(spec) == 2 && spec[0] == "host" && isIPv4(spec[1]):
		e.Net, e.Wild = netip.MustParseAddr(spec[1]), zero
	case len(spec) == 1 && isIPv4(spec[0]):
		e.Net, e.Wild = netip.MustParseAddr(spec[0]), zero
	case len(spec) == 2 && isIPv4(spec[0]) && isIPv4(spec[1]):
		e.Net, e.Wild = netip.MustParseAddr(spec[0]), netip.MustParseAddr(spec[1])
	default:
		return e, false, false
	}
	return e, false, true
}

// ---- ip helper-address ----

// Helper es un `ip helper-address` de una interfaz; Options trae vrf/global si los lleva.
type Helper struct {
	Addr    string
	Options []string
}

func ParseHelpers(c InterfaceConfig) []Helper {
	var out []Helper
	for _, l := range c.Lines {
		f := strings.Fields(l)
		if len(f) < 3 || f[0] != "ip" || f[1] != "helper-address" {
			continue
		}
		switch {
		case f[2] == "vrf" && len(f) >= 5:
			out = append(out, Helper{Addr: f[4], Options: f[2:4]})
		case f[2] == "global" && len(f) >= 4:
			out = append(out, Helper{Addr: f[3], Options: f[2:3]})
		default:
			h := Helper{Addr: f[2]}
			if len(f) > 3 {
				h.Options = f[3:]
			}
			out = append(out, h)
		}
	}
	return out
}
