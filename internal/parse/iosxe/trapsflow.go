package iosxe

import (
	"slices"
	"strconv"
)

// Lectores de la plantilla snmp-trap-host y netflow-export (sin validar en laboratorio).

// SNMPHost es un `snmp-server host`: solo el destino y el puerto UDP (162 si no se escribe). La community o el usuario que lleva la
// línea no se guarda: el parser no la lleva a ninguna parte.
type SNMPHost struct {
	Addr string
	Port int
}

// ParseSNMPHosts lee las líneas `snmp-server host ADDR [vrf V] [informs|traps] [version V [auth|noauth|priv]] COMUNIDAD [udp-port N] [tipos...]`.
func ParseSNMPHosts(text string) ([]SNMPHost, bool) {
	var out []SNMPHost
	for _, f := range cfgFields(text) {
		if len(f) < 4 || f[0] != "snmp-server" || f[1] != "host" {
			continue
		}
		h := SNMPHost{Addr: f[2], Port: 162}
		i := 3
	opts:
		for i < len(f) {
			switch f[i] {
			case "vrf", "use-vrf":
				i += 2
			case "informs", "traps":
				i++
			case "version":
				i += 2
				if i-1 < len(f) && f[i-1] == "3" && i < len(f) && slices.Contains([]string{"auth", "noauth", "priv"}, f[i]) {
					i++
				}
			default:
				break opts
			}
		}
		i++ // la community o el usuario
		for ; i+1 < len(f); i++ {
			if f[i] == "udp-port" {
				if n, err := strconv.Atoi(f[i+1]); err == nil {
					h.Port = n
				}
			}
		}
		out = append(out, h)
	}
	if len(out) == 0 && readFailed(text) {
		return nil, false
	}
	return out, true
}

// snmpTrapAll son los traps de `snmp-server enable traps snmp` sin argumentos.
var snmpTrapAll = []string{"authentication", "linkdown", "linkup", "warmstart", "coldstart"}

// SNMPTraps son los traps activos según las líneas `snmp-server enable traps`. All: la línea sin familia los activa todos.
type SNMPTraps struct {
	All    bool
	Snmp   map[string]bool
	Config bool
}

func (t SNMPTraps) HasSnmp(name string) bool { return t.All || t.Snmp[name] }
func (t SNMPTraps) HasConfig() bool          { return t.All || t.Config }

func ParseSNMPTraps(text string) (SNMPTraps, bool) {
	t := SNMPTraps{Snmp: map[string]bool{}}
	seen := false
	for _, f := range cfgFields(text) {
		if len(f) < 3 || f[0] != "snmp-server" || f[1] != "enable" || f[2] != "traps" {
			continue
		}
		seen = true
		switch {
		case len(f) == 3:
			t.All = true
		case f[3] == "config" && len(f) == 4:
			t.Config = true
		case f[3] == "snmp":
			args := f[4:]
			if len(args) == 0 {
				args = snmpTrapAll
			}
			for _, a := range args {
				t.Snmp[a] = true
			}
		}
	}
	if !seen && readFailed(text) {
		return SNMPTraps{}, false
	}
	return t, true
}

// FlowObjects son los nombres de los records, exporters y monitors de Flexible NetFlow de un `show running-config | section ^flow`.
type FlowObjects struct{ Records, Exporters, Monitors []string }

func ParseFlowObjects(text string) (FlowObjects, bool) {
	var o FlowObjects
	for _, f := range cfgFields(text) {
		if len(f) != 3 || f[0] != "flow" {
			continue
		}
		switch f[1] {
		case "record":
			o.Records = append(o.Records, f[2])
		case "exporter":
			o.Exporters = append(o.Exporters, f[2])
		case "monitor":
			o.Monitors = append(o.Monitors, f[2])
		}
	}
	if len(o.Records)+len(o.Exporters)+len(o.Monitors) == 0 && readFailed(text) {
		return FlowObjects{}, false
	}
	return o, true
}
