package iosxe

import "strings"

// L2Port son las líneas de una interfaz que tocan las plantillas L2 por puerto (velocidad, tormentas, portfast, BPDU guard y
// port-security), tal como las escribe el running-config. Cada campo vacío es «sin la línea»: IOS no muestra los valores por defecto.
type L2Port struct {
	// Speed y Duplex guardan lo que sigue a la palabra entero («100», «auto 10 100»): la plantilla decide si lo sabe restaurar.
	Speed, Duplex string
	// Storm: tipo (broadcast, multicast, unicast) → lo que sigue al tipo («level 20.00», «level 20.00 10.00», «level bps 1m»...).
	Storm map[string]string
	// StormActions son las acciones activas: shutdown y trap son banderas independientes y pueden estar las dos, cada una en su línea.
	StormActions []string
	// HasPortfast dice que hay una línea «spanning-tree portfast»; Portfast es lo que le sigue (vacío, «edge», «trunk», «disable», «network»).
	HasPortfast  bool
	Portfast     string
	Bpduguard    string   // enable o disable; «?» si la línea no lleva argumento
	PortSecurity []string // cada línea «switchport port-security ...» completa
}

// ParseL2Port lee de la configuración de una interfaz (ParseInterfaceConfig) lo que importa a las plantillas L2 por puerto.
// Formatos de la documentación de Cisco; sin validar en laboratorio.
func ParseL2Port(c InterfaceConfig) L2Port {
	var p L2Port
	for _, l := range c.Lines {
		f := strings.Fields(strings.ToLower(l))
		switch {
		case len(f) >= 2 && f[0] == "speed":
			p.Speed = strings.Join(f[1:], " ")
		case len(f) >= 2 && f[0] == "duplex":
			p.Duplex = strings.Join(f[1:], " ")
		case len(f) >= 3 && f[0] == "storm-control" && f[1] == "action":
			p.StormActions = append(p.StormActions, strings.Join(f[2:], " "))
		case len(f) >= 3 && f[0] == "storm-control":
			if p.Storm == nil {
				p.Storm = map[string]string{}
			}
			p.Storm[f[1]] = strings.Join(f[2:], " ")
		case len(f) >= 2 && f[0] == "spanning-tree" && f[1] == "portfast":
			p.HasPortfast, p.Portfast = true, strings.Join(f[2:], " ")
		case len(f) >= 2 && f[0] == "spanning-tree" && f[1] == "bpduguard":
			p.Bpduguard = ifEmpty(strings.Join(f[2:], " "), "?")
		case len(f) >= 2 && f[0] == "switchport" && f[1] == "port-security":
			p.PortSecurity = append(p.PortSecurity, strings.Join(strings.Fields(l), " "))
		}
	}
	return p
}

// ErrdisableRecovery es lo que `show running-config | include errdisable recovery` muestra: las causas activas y el intervalo si no es el de fábrica.
type ErrdisableRecovery struct {
	Causes   []string
	Interval string // vacío = el de fábrica (300 s)
}

// ParseErrdisableRecovery lee esa salida. Sin coincidencias IOS no imprime nada (equipo sin recuperación, ok=true); ok=false si trae un
// aviso de error o una línea de errdisable recovery que no se entiende. Formato de la documentación de Cisco; sin validar en laboratorio.
func ParseErrdisableRecovery(text string) (ErrdisableRecovery, bool) {
	var r ErrdisableRecovery
	for _, raw := range lines(text) {
		l := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if l == "" {
			continue
		}
		f := strings.Fields(strings.ToLower(l))
		switch {
		case len(f) >= 4 && f[0] == "errdisable" && f[1] == "recovery" && f[2] == "cause":
			r.Causes = append(r.Causes, strings.Join(f[3:], " ")) // también las que no conocemos («channel-misconfig (stp)»): están activas y no se tocan
		case len(f) == 4 && f[0] == "errdisable" && f[1] == "recovery" && f[2] == "interval" && digits(f[3]):
			r.Interval = f[3]
		default:
			return ErrdisableRecovery{}, false
		}
	}
	return r, true
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func ifEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
