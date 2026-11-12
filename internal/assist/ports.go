package assist

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// ifaceRe acepta solo puertos físicos: nunca Port-channel, Vlan, Loopback, Tunnel ni subinterfaces.
var ifaceRe = regexp.MustCompile(`(?i)^(gigabitethernet|tengigabitethernet|fastethernet|twentyfivegige|fortygigabitethernet|hundredgige|ethernet|gi|te|fa|twe|fo|hu|eth)\d+(/\d+){0,3}$`)

// ValidInterface dice si name es un puerto físico que la función ports acepta.
func ValidInterface(name string) bool { return ifaceRe.MatchString(name) }

func vlanOK(s string) error {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 4094 {
		return fmt.Errorf("VLAN %q fuera de 1-4094", s)
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
				return errors.New("solo un puerto físico (nada de Port-channel, Vlan, rangos ni subinterfaces)")
			}
		case strings.HasPrefix(l, "switchport access vlan ") || strings.HasPrefix(l, "switchport voice vlan "):
			if len(f) != 4 {
				return errors.New("falta la VLAN o sobran argumentos")
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
				return errors.New("solo access, dynamic auto o dynamic desirable")
			}
		case strings.HasPrefix(l, "no switchport mode"):
			if strings.Join(strings.Fields(l), " ") != "no switchport mode" {
				return errors.New("no switchport mode va sin argumentos") // con argumento también devuelve el puerto a dynamic
			}
		case strings.HasPrefix(l, "no switchport "):
			if len(f) != 4 {
				return errors.New("sin argumentos")
			}
		case l == "shutdown" || l == "no shutdown" || l == "no description" || strings.Join(f, " ") == "no spanning-tree portfast":
		case strings.HasPrefix(l, "description"):
			if len(line) > len("description ")+200 {
				return errors.New("descripción de más de 200 caracteres")
			}
		default:
			return errors.New("no reconocida")
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
		return nil, errors.New("indica al menos una interfaz")
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range ifaces {
		if !ValidInterface(n) {
			return nil, fmt.Errorf("%q no es un puerto físico (se rechazan Port-channel, Vlan, Loopback, rangos y subinterfaces)", n)
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
			return fmt.Errorf("VLAN %d fuera de 1-4094", v)
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

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrPortRefused, fmt.Sprintf(format, a...))
}

// accessPort exige un puerto de acceso: switchport mode access en la captura, o Administrative
// Mode static access en show interfaces X switchport. Un puerto dynamic auto/desirable (el valor de
// fábrica de un Catalyst de acceso) también sirve si no está operando como trunk; entonces
// toAccess es true y el plan le pone switchport mode access.
func accessPort(n string, cur iosxe.InterfaceConfig, switchport string) (toAccess bool, err error) {
	switch {
	case cur.Trunk || cur.ChannelGroup || cur.Routed:
		return false, refuse("%s es trunk, miembro de un canal o puerto ruteado", n)
	case cur.L3:
		return false, refuse("%s tiene dirección IP, VRF o NAT: es un puerto de capa 3 (¿administración?)", n)
	case cur.AccessVlan != "" && cur.AccessVlan != "dynamic" && !digits(cur.AccessVlan):
		return false, refuse("%s tiene una VLAN de acceso que no se puede restaurar (%s)", n, cur.AccessVlan)
	case cur.AccessVlan == "dynamic":
		return false, refuse("%s usa VLAN de acceso dinámica (VMPS)", n)
	case cur.Mode == "access":
		return false, nil
	case cur.Mode != "" && !isDynamicMode(cur.Mode):
		return false, refuse("%s está en modo %q, no en acceso", n, cur.Mode)
	}
	admin, ok := iosxe.ParseSwitchportMode(switchport)
	switch {
	case cur.Mode == "" && ok && admin == "static access":
		return false, nil
	case cur.Mode == "" && !ok:
		return false, refuse("%s no es un puerto de acceso: sin switchport mode access ni Administrative Mode static access", n)
	case cur.Mode == "" && !isDynamicMode(admin):
		return false, refuse("%s está en modo administrativo %q, no es un puerto de acceso (pon switchport mode access)", n, admin)
	}
	// dynamic auto/desirable: solo si no negoció un trunk (cambiarlo podría cortar tráfico).
	oper, ok := iosxe.ParseSwitchportOperMode(switchport)
	switch {
	case !ok:
		return false, refuse("%s está en modo dynamic y no se pudo leer su Operational Mode en show interfaces switchport: no se sabe si negoció un trunk", n)
	case oper == "trunk":
		return false, refuse("%s está en modo dynamic y opera como trunk (un vecino negoció el enlace): cambiarlo podría cortar tráfico", n)
	case oper != "down" && oper != "static access": // lista cerrada: otro modo operativo (private-vlan, tunnel...) no se toca
		return false, refuse("%s está en modo dynamic y opera como %q, no como acceso", n, oper)
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
		return refuse("la VLAN %d no existe en %s: IOS la crearía y, si el equipo es servidor VTP, la propagaría al dominio; créala por separado", id, device)
	case st != "active":
		return refuse("la VLAN %d de %s está en estado %q, no activa: el puerto quedaría inactivo", id, device, st)
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
		return DevicePlan{}, errors.New("no hay nada que cambiar: indica VLAN, VLAN de voz, descripción o shut/no shut")
	}
	for _, v := range vlansToCheck(ch) {
		out, ok := outs[showVlan(v)]
		if !ok {
			return DevicePlan{}, fmt.Errorf("falta la salida de %q", showVlan(v))
		}
		if err := vlanExists(device, v, out); err != nil {
			return DevicePlan{}, err
		}
	}
	var desc string
	if ch.Description != nil {
		if err := asciiOnly(*ch.Description); err != nil { // antes de recortar: "x\r" no puede quedar como "x"
			return DevicePlan{}, fmt.Errorf("descripción: %w", err)
		}
		if desc = strings.TrimSpace(*ch.Description); strings.ContainsAny(desc, "?\r\n\t") || len(desc) > 200 {
			return DevicePlan{}, errors.New("la descripción no admite '?' ni saltos de línea y mide como máximo 200 caracteres")
		}
	}
	dp := DevicePlan{Device: device, Pre: pre, Baseline: map[string]string{}}
	var rollback [][]string
	for _, n := range names {
		text, ok := outs[showCfg(n)]
		if !ok {
			return DevicePlan{}, fmt.Errorf("falta la configuración capturada de %s", n)
		}
		cur, ok := iosxe.ParseInterfaceConfig(text)
		if !ok || !strings.EqualFold(iosxe.ShortIf(cur.Name), iosxe.ShortIf(n)) {
			return DevicePlan{}, fmt.Errorf("la captura de %s no es la configuración de esa interfaz", n)
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
