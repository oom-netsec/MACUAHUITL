package iosxe

import (
	"strconv"
	"strings"
)

// InterfaceConfig es el bloque de una interfaz en `show running-config interface X`.
type InterfaceConfig struct {
	Name           string
	Description    string
	HasDescription bool
	AccessVlan     string // lo que sigue a "switchport access vlan" ("10", "dynamic"); vacío = sin la línea (VLAN 1 por defecto)
	VoiceVlan      string // lo que sigue a "switchport voice vlan" ("110", "dot1p", "untagged", "none"); vacío = sin la línea
	Shutdown       bool
	Mode           string   // "access", "trunk", "dynamic auto"... tal como lo escribe "switchport mode"
	Trunk          bool     // modo trunk o cualquier línea "switchport trunk"
	Routed         bool     // "no switchport"
	ChannelGroup   bool     // miembro de un Port-channel
	TrunkAllowed   []string // líneas "switchport trunk allowed vlan ..." en el orden del running-config
	L3             bool     // ip address, ipv6 address, ip unnumbered, vrf forwarding o ip nat: interfaz de capa 3
	Lines          []string
}

// ParseInterfaceConfig lee la salida de `show running-config interface X`.
// ok=false si no trae una línea "interface ...": no se toma como interfaz sin configuración.
func ParseInterfaceConfig(text string) (InterfaceConfig, bool) {
	var c InterfaceConfig
	in := false
	for _, raw := range lines(text) {
		l := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		switch {
		case strings.HasPrefix(l, "interface "):
			if in {
				return c, true // un segundo bloque no es de esta interfaz
			}
			in, c.Name = true, strings.TrimSpace(strings.TrimPrefix(l, "interface "))
			continue
		case !in || l == "" || l == "!":
			continue
		case l == "end":
			return c, true
		}
		c.Lines = append(c.Lines, l)
		low := strings.ToLower(l)
		f := strings.Fields(low)
		switch {
		case strings.HasPrefix(low, "description"):
			c.HasDescription, c.Description = true, strings.TrimSpace(strings.TrimPrefix(l, l[:len("description")]))
		case strings.HasPrefix(low, "switchport access vlan "):
			c.AccessVlan = f[len(f)-1]
		case strings.HasPrefix(low, "switchport voice vlan "):
			c.VoiceVlan = f[len(f)-1]
		case strings.HasPrefix(low, "switchport mode "):
			c.Mode = strings.TrimPrefix(low, "switchport mode ")
			c.Trunk = c.Trunk || c.Mode == "trunk"
		case strings.HasPrefix(low, "switchport trunk"):
			c.Trunk = true
			if strings.HasPrefix(low, "switchport trunk allowed vlan") {
				c.TrunkAllowed = append(c.TrunkAllowed, l)
			}
		case strings.HasPrefix(low, "ip address "), strings.HasPrefix(low, "ipv6 address "), strings.HasPrefix(low, "vrf forwarding"),
			strings.HasPrefix(low, "ip vrf forwarding"), strings.HasPrefix(low, "ip nat "),
			strings.HasPrefix(low, "ip unnumbered "), strings.HasPrefix(low, "ipv6 unnumbered "):
			c.L3 = true
		case low == "no switchport":
			c.Routed = true
		case low == "shutdown":
			c.Shutdown = true
		case strings.HasPrefix(low, "channel-group "):
			c.ChannelGroup = true
		}
	}
	return c, in
}

// ParseSwitchportMode lee "Administrative Mode:" de `show interfaces X switchport` ("static access",
// "dynamic auto", "trunk"...). ok=false si no hay esa línea (p. ej. puerto ruteado: "Switchport: Disabled").
func ParseSwitchportMode(text string) (mode string, ok bool) {
	return switchportField(text, "Administrative Mode:")
}

// ParseSwitchportOperMode lee "Operational Mode:" ("static access", "trunk", "down"...): lo que el puerto
// negoció de verdad, a diferencia del modo administrativo. ok=false si no hay esa línea.
func ParseSwitchportOperMode(text string) (mode string, ok bool) {
	return switchportField(text, "Operational Mode:")
}

func switchportField(text, prefix string) (string, bool) {
	for _, l := range lines(text) {
		if v, found := strings.CutPrefix(strings.TrimSpace(l), prefix); found {
			return strings.ToLower(strings.TrimSpace(v)), true
		}
	}
	return "", false
}

// ParseVlanID lee `show vlan id N`: el estado de la VLAN (active, suspend, act/lshut...) si existe.
func ParseVlanID(text string, id int) (status string, found bool) {
	for _, l := range lines(text) {
		f := strings.Fields(l)
		if len(f) >= 3 && f[0] == strconv.Itoa(id) {
			return strings.ToLower(f[2]), true
		}
	}
	return "", false
}
