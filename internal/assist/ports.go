package assist

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// ifaceRe acepta solo puertos físicos: nunca Port-channel, Vlan, Loopback, Tunnel ni subinterfaces.
var ifaceRe = regexp.MustCompile(`(?i)^(gigabitethernet|tengigabitethernet|fastethernet|twentyfivegige|fortygigabitethernet|hundredgige|ethernet|gi|te|fa|twe|fo|hu|eth)\d+(/\d+){0,3}$`)

// ValidInterface dice si name es un puerto físico que la función ports acepta.
func ValidInterface(name string) bool { return ifaceRe.MatchString(name) }

func vlanOK(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 4094 {
		return cerr("assist.err.vlan_range_quoted", "value", s)
	}
	return nil
}

// Ports es la lista cerrada de la función de puertos de acceso: interfaz, VLAN de acceso y de
// voz, descripción, shutdown y, en un puerto dynamic, el paso a access (y su reversa). Nada de modo trunk, canales ni VLANs de otro tipo.
var Ports = Function{
	Name: "ports",
	Allowed: []string{"interface", "switchport access vlan", "switchport voice vlan", "no switchport access vlan",
		"no switchport voice vlan", "switchport mode", "no switchport mode", "description", "no description", "shutdown", "no shutdown",
		"no spanning-tree portfast"},
	Check: func(line string) error {
		f := strings.Fields(line)
		l := strings.ToLower(line)
		switch {
		case strings.EqualFold(f[0], "interface"):
			if len(f) != 2 || !ValidInterface(f[1]) {
				return cerr("assist.err.single_physical_port")
			}
		case strings.HasPrefix(l, "switchport access vlan ") || strings.HasPrefix(l, "switchport voice vlan "):
			if len(f) != 4 {
				return cerr("assist.err.vlan_missing_or_extra")
			}
			// La reversa restaura tal cual la VLAN de voz que tenía el puerto (dot1p, untagged o none).
			if f[1] == "voice" && (f[3] == "dot1p" || f[3] == "untagged" || f[3] == "none") {
				return nil
			}
			return vlanOK(f[3])
		case strings.HasPrefix(l, "switchport mode "):
			// Solo pasar a acceso o devolver el puerto a su modo dinámico: nunca trunk.
			switch strings.Join(strings.Fields(l), " ") {
			case "switchport mode access", "switchport mode dynamic auto", "switchport mode dynamic desirable":
			default:
				return cerr("assist.err.mode_values")
			}
		case strings.HasPrefix(l, "no switchport mode"):
			if strings.Join(strings.Fields(l), " ") != "no switchport mode" {
				return cerr("assist.err.no_switchport_mode_args") // con argumento también devuelve el puerto a dynamic
			}
		case strings.HasPrefix(l, "no switchport "):
			if len(f) != 4 {
				return cerr("assist.err.no_arguments")
			}
		case l == "shutdown" || l == "no shutdown" || l == "no description" || strings.Join(f, " ") == "no spanning-tree portfast":
		case strings.HasPrefix(l, "description"):
			if len(line) > len("description ")+200 {
				return cerr("assist.err.description_too_long")
			}
		default:
			return cerr("assist.err.not_recognized")
		}
		return nil
	},
}

// ErrPortRefused: el puerto no es uno que esta función pueda cambiar (trunk, canal, ruteado).
var ErrPortRefused = errors.New("assist: puerto no apto para el aprovisionamiento de acceso")

// PortChange son los cambios pedidos a cada puerto. Vlan y Voice en 0, Description nil y
// Shutdown nil significan "no tocar"; Description "" quita la descripción.
type PortChange struct {
	Vlan, Voice int
	Description *string
	Shutdown    *bool // true = shutdown, false = no shutdown
}

var portfastRe = regexp.MustCompile(`(?m)^\s+spanning-tree portfast\b`)

func showCfg(iface string) string        { return "show running-config interface " + iface }
func showStatus(iface string) string     { return "show interfaces " + iface + " status" }
func showSwitchport(iface string) string { return "show interfaces " + iface + " switchport" }
func showVlan(id int) string             { return fmt.Sprintf("show vlan id %d", id) }

// normIfaces rechaza lo que no es un puerto físico y quita repetidos (Gi1/0/1 y gigabitethernet1/0/1
// son el mismo): se conserva la primera escritura.
func normIfaces(ifaces []string) ([]string, error) {
	if len(ifaces) == 0 {
		return nil, cerr("assist.err.interface_required")
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range ifaces {
		if !ValidInterface(n) {
			return nil, cerr("assist.err.not_physical_port", "port", n)
		}
		if k := strings.ToLower(iosxe.ShortIf(n)); !seen[k] {
			seen[k] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func checkVlans(ch PortChange) error {
	for _, v := range []int{ch.Vlan, ch.Voice} {
		if v < 0 || v > 4094 {
			return cerr("assist.err.vlan_range", "vlan", v)
		}
	}
	return nil
}

// vlansToCheck son las VLAN que el cambio nombra, sin repetir.
func vlansToCheck(ch PortChange) []int {
	var out []int
	for _, v := range []int{ch.Vlan, ch.Voice} {
		if v != 0 && (len(out) == 0 || out[0] != v) {
			out = append(out, v)
		}
	}
	return out
}

// PortsPre devuelve los comandos de lectura que hay que correr antes de planear: por puerto, su
// configuración (de ahí sale la reversa), su estado y su modo de switchport; y por cada VLAN
// nombrada, show vlan id (IOS crea la VLAN que no existe y, con VTP servidor, la propaga).
func PortsPre(ifaces []string, ch PortChange) ([]string, error) {
	names, err := normIfaces(ifaces)
	if err != nil {
		return nil, err
	}
	if err := checkVlans(ch); err != nil {
		return nil, err
	}
	var pre []string
	for _, n := range names {
		pre = append(pre, showCfg(n), showStatus(n), showSwitchport(n))
	}
	for _, v := range vlansToCheck(ch) {
		pre = append(pre, showVlan(v))
	}
	return pre, nil
}

func refuse(code string, kv ...any) error {
	return newRefusal(ErrPortRefused, "assist.port_refused", i18n.Tx(code, kv...))
}

// accessPort exige un puerto de acceso: switchport mode access en la captura, o Administrative
// Mode static access en show interfaces X switchport. Un puerto dynamic auto/desirable (el valor de
// fábrica de un Catalyst de acceso) también sirve si no está operando como trunk; entonces
// toAccess es true y el plan le pone switchport mode access.
func accessPort(n string, cur iosxe.InterfaceConfig, switchport string) (toAccess bool, err error) {
	switch {
	case cur.Trunk || cur.ChannelGroup || cur.Routed:
		return false, refuse("assist.port_refused.es_trunk_miembro_de_un", "port", n)
	case cur.L3:
		return false, refuse("assist.port_refused.tiene_direccion_ip_vrf_o", "port", n)
	case cur.AccessVlan != "" && cur.AccessVlan != "dynamic" && !digits(cur.AccessVlan):
		return false, refuse("assist.port_refused.tiene_una_vlan_de_acceso", "port", n, "vlan", cur.AccessVlan)
	case cur.AccessVlan == "dynamic":
		return false, refuse("assist.port_refused.usa_vlan_de_acceso_dinamica", "port", n)
	case cur.Mode == "access":
		return false, nil
	case cur.Mode != "" && !isDynamicMode(cur.Mode):
		return false, refuse("assist.port_refused.esta_en_modo_no_en", "port", n, "mode", cur.Mode)
	}
	admin, ok := iosxe.ParseSwitchportMode(switchport)
	switch {
	case cur.Mode == "" && ok && admin == "static access":
		return false, nil
	case cur.Mode == "" && !ok:
		return false, refuse("assist.port_refused.no_es_un_puerto_de", "port", n)
	case cur.Mode == "" && !isDynamicMode(admin):
		return false, refuse("assist.port_refused.esta_en_modo_administrativo_no", "port", n, "admin", admin)
	}
	// dynamic auto/desirable: solo si no negoció un trunk (cambiarlo podría cortar tráfico).
	oper, ok := iosxe.ParseSwitchportOperMode(switchport)
	switch {
	case !ok:
		return false, refuse("assist.port_refused.esta_en_modo_dynamic_y", "port", n)
	case oper == "trunk":
		return false, refuse("assist.port_refused.esta_en_modo_dynamic_y2", "port", n)
	case oper != "down" && oper != "static access": // lista cerrada: otro modo operativo (private-vlan, tunnel...) no se toca
		return false, refuse("assist.port_refused.esta_en_modo_dynamic_y3", "port", n, "oper", oper)
	}
	return true, nil
}

func isDynamicMode(m string) bool { return m == "dynamic auto" || m == "dynamic desirable" }

func digits(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n > 0
}

// vlanExists exige que la VLAN exista y esté activa en el equipo.
func vlanExists(device string, id int, out string) error {
	st, found := iosxe.ParseVlanID(out, id)
	switch {
	case !found:
		return refuse("assist.port_refused.la_vlan_no_existe_en", "id", id, "device", device)
	case st != "active":
		return refuse("assist.port_refused.la_vlan_de_esta_en", "id", id, "device", device, "status", st)
	}
	return nil
}

// PortsPlan arma el plan de un equipo. outs trae, por comando de PortsPre, la salida tomada
// antes de planear: de la configuración de cada puerto sale la reversa, que restaura exactamente esos valores.
func PortsPlan(device string, ifaces []string, ch PortChange, outs map[string]string) (DevicePlan, error) {
	pre, err := PortsPre(ifaces, ch)
	if err != nil {
		return DevicePlan{}, err
	}
	names, _ := normIfaces(ifaces)
	if ch.Vlan == 0 && ch.Voice == 0 && ch.Description == nil && ch.Shutdown == nil {
		return DevicePlan{}, cerr("assist.err.ports_nothing_to_change")
	}
	for _, v := range vlansToCheck(ch) {
		out, ok := outs[showVlan(v)]
		if !ok {
			return DevicePlan{}, cerr("assist.err.output_missing", "command", showVlan(v))
		}
		if err := vlanExists(device, v, out); err != nil {
			return DevicePlan{}, err
		}
	}
	var desc string
	if ch.Description != nil {
		if err := asciiOnly(*ch.Description); err != nil { // antes de recortar: "x\r" no puede quedar como "x"
			return DevicePlan{}, withPrefix("assist.err.description_invalid", err)
		}
		if desc = strings.TrimSpace(*ch.Description); strings.ContainsAny(desc, "?\r\n\t") || len(desc) > 200 {
			return DevicePlan{}, cerr("assist.err.description_rule_lines")
		}
	}
	dp := DevicePlan{Device: device, Pre: pre, Baseline: map[string]string{}}
	var rollback [][]string
	for _, n := range names {
		text, ok := outs[showCfg(n)]
		if !ok {
			return DevicePlan{}, cerr("assist.err.capture_missing", "port", n)
		}
		cur, ok := iosxe.ParseInterfaceConfig(text)
		if !ok || !strings.EqualFold(iosxe.ShortIf(cur.Name), iosxe.ShortIf(n)) {
			return DevicePlan{}, cerr("assist.err.capture_mismatch", "port", n)
		}
		toAccess, err := accessPort(n, cur, outs[showSwitchport(n)])
		if err != nil {
			return DevicePlan{}, err
		}
		// Solo una VLAN de acceso o de voz exige modo access: descripción y shut/no shut no tocan el modo del puerto.
		toAccess = toAccess && (ch.Vlan != 0 || ch.Voice != 0)
		dp.Baseline[showCfg(n)] = text
		dp.Post = append(dp.Post, showCfg(n), showStatus(n))
		ex := func(line string, present, prefix bool) {
			dp.Expect = append(dp.Expect, Expect{Command: showCfg(n), Line: line, Present: present, Prefix: prefix})
		}
		apply, back := []string{"interface " + n}, []string{"interface " + n}
		if toAccess {
			// DTP no toca el running-config: sin esto, un trunk negociado entre el plan y el aplicar no se notaría.
			dp.Baseline[showSwitchport(n)] = outs[showSwitchport(n)]
			apply = append(apply, "switchport mode access")
			ex("switchport mode access", true, false)
		}
		if ch.Vlan != 0 {
			apply = append(apply, fmt.Sprintf("switchport access vlan %d", ch.Vlan))
			back = append(back, ifElse(cur.AccessVlan != "", "switchport access vlan "+cur.AccessVlan, "no switchport access vlan"))
			if ch.Vlan == 1 { // IOS no muestra el valor por defecto: la línea desaparece
				ex("switchport access vlan", false, true)
			} else {
				ex(fmt.Sprintf("switchport access vlan %d", ch.Vlan), true, false)
			}
		}
		if ch.Voice != 0 {
			apply = append(apply, fmt.Sprintf("switchport voice vlan %d", ch.Voice))
			back = append(back, ifElse(cur.VoiceVlan != "", "switchport voice vlan "+cur.VoiceVlan, "no switchport voice vlan"))
			ex(fmt.Sprintf("switchport voice vlan %d", ch.Voice), true, false)
			// IOS agrega solo «spanning-tree portfast edge» al poner la VLAN de voz y no lo quita al quitarla (así lo documenta Cisco).
			if !portfastRe.MatchString(text) {
				back = append(back, "no spanning-tree portfast")
			}
		}
		if ch.Description != nil {
			if desc == "" {
				apply = append(apply, "no description")
				ex("description", false, true)
			} else {
				apply = append(apply, "description "+desc)
				ex("description "+desc, true, false)
			}
			back = append(back, ifElse(cur.HasDescription, "description "+cur.Description, "no description"))
		}
		if ch.Shutdown != nil {
			apply = append(apply, ifElse(*ch.Shutdown, "shutdown", "no shutdown"))
			back = append(back, ifElse(cur.Shutdown, "shutdown", "no shutdown"))
			ex("shutdown", *ch.Shutdown, false)
		}
		for _, bad := range []string{"inactive", "err-disabled"} { // el puerto no puede quedar sin VLAN ni caído por error
			dp.Expect = append(dp.Expect, Expect{Command: showStatus(n), Line: bad, Column: "status"})
		}
		if toAccess {
			// El modo dynamic auto de fábrica no sale en el running-config (cur.Mode vacío): "no switchport mode"
			// devuelve el puerto a ese valor por defecto, que es exactamente el estado anterior. Un modo explícito
			// (dynamic desirable, o dynamic auto escrito a mano) se restaura tal cual.
			back = append(back, ifElse(cur.Mode != "", "switchport mode "+cur.Mode, "no switchport mode"))
		}
		dp.Apply = append(dp.Apply, apply...)
		rollback = append(rollback, back)
	}
	for i := len(rollback) - 1; i >= 0; i-- { // la reversa va en orden inverso
		dp.Rollback = append(dp.Rollback, rollback[i]...)
	}
	// Lo que la reversa no pueda restaurar (p. ej. una descripción con '?') rompe el plan aquí, no a mitad del cambio.
	if err := Validate(Plan{Function: Ports.Name, Devices: []DevicePlan{dp}}, Ports); err != nil {
		return DevicePlan{}, err
	}
	return dp, nil
}

func ifElse(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}
