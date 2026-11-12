package iosxe

import (
	"regexp"
	"strconv"
	"strings"
)

// VlanRow es una fila de la tabla de `show vlan brief` o `show vlan id N`. Ports son los puertos de acceso asignados
// (en `show vlan brief`; las líneas de continuación los completan).
type VlanRow struct {
	ID           int
	Name, Status string
	Ports        []string
}

var vlanRowRe = regexp.MustCompile(`^(\d{1,4})\s+(\S+)\s+(\S+)(?:\s+(.*))?$`)

// vlanPorts agrega los puertos de una línea de la columna Ports. Cualquier elemento cuenta como puerto, aunque no
// se reconozca su nombre: dejar uno fuera haría pasar por vacía una VLAN que tiene puertos.
func vlanPorts(s string, into []string) []string {
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			into = append(into, p)
		}
	}
	return into
}

// ParseVlanBrief lee la tabla de VLAN (la primera: la del tipo y MTU de show vlan id N no se mezcla);
// ok=false si no trae el encabezado ni filas.
func ParseVlanBrief(text string) ([]VlanRow, bool) {
	var rows []VlanRow
	head := false
	for _, l := range lines(text) {
		if strings.HasPrefix(l, "VLAN Name") {
			head = true
			continue
		}
		if strings.HasPrefix(l, "VLAN Type") {
			break
		}
		l = strings.TrimRight(l, " \r")
		if m := vlanRowRe.FindStringSubmatch(l); m != nil && head {
			id, _ := strconv.Atoi(m[1])
			rows = append(rows, VlanRow{ID: id, Name: m[2], Status: strings.ToLower(m[3]), Ports: vlanPorts(m[4], nil)})
		} else if head && len(rows) > 0 && (strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t")) {
			last := &rows[len(rows)-1]
			last.Ports = vlanPorts(l, last.Ports)
		}
	}
	return rows, head
}

// VlanDetail es lo que `show vlan id N` dice de una VLAN más allá de su nombre: lo que una reversa de `vlan N` +
// `name X` no restauraría si no fuera el valor por omisión.
type VlanDetail struct {
	Type    string // enet, fddi, tr...
	MTU     int
	RSPAN   bool // Remote SPAN VLAN habilitada
	Private bool // alguna fila de VLAN privada (primaria/secundaria)
}

// ParseVlanDetail lee la fila de tipo y MTU de la VLAN id, el estado de Remote SPAN y la tabla de VLAN privadas;
// ok=false si falta cualquiera de las dos primeras (no se puede afirmar nada).
func ParseVlanDetail(text string, id int) (VlanDetail, bool) {
	var d VlanDetail
	var hasRow, hasSPAN bool
	section := ""
	for _, l := range lines(text) {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "VLAN Type"):
			section = "type"
		case t == "Remote SPAN VLAN":
			section = "rspan"
		case strings.HasPrefix(t, "Primary") && strings.Contains(t, "Secondary"):
			section = "pvlan"
		case t == "" || strings.HasPrefix(t, "---") || strings.HasPrefix(t, "VLAN Name"):
		case section == "type":
			if f := strings.Fields(t); len(f) >= 4 && f[0] == strconv.Itoa(id) {
				d.Type, d.MTU, hasRow = f[1], int(atoi(f[3])), true
			}
		case section == "rspan":
			d.RSPAN, hasSPAN = strings.EqualFold(t, "Enabled"), true
		case section == "pvlan":
			d.Private = true
		}
	}
	return d, hasRow && hasSPAN
}

// TrunkVlans son las VLAN activas del dominio de administración que viajan por un trunk
// (tercera tabla de `show interfaces trunk`).
type TrunkVlans struct {
	Port  string
	Vlans map[int]bool
}

// ParseTrunkActive lee la tabla «Vlans allowed and active in management domain» con sus líneas de continuación;
// ok=false si no está su cabecera.
func ParseTrunkActive(text string) ([]TrunkVlans, bool) {
	var out []TrunkVlans
	in := false
	for _, l := range lines(text) {
		f := strings.Fields(l)
		switch {
		case strings.Contains(l, "Vlans allowed and active in management domain"):
			in = true
		case !in:
		case len(f) == 0:
			return out, true // fin de la tabla
		case strings.HasPrefix(l, "Port"):
			return out, true // la tabla siguiente
		case strings.HasPrefix(l, " ") && len(out) > 0:
			for _, id := range vlanList(strings.Join(f, "")) {
				out[len(out)-1].Vlans[id] = true
			}
		case len(f) >= 2:
			v := map[int]bool{}
			for _, id := range vlanList(strings.Join(f[1:], "")) {
				v[id] = true
			}
			out = append(out, TrunkVlans{ShortIf(f[0]), v})
		}
	}
	return out, in
}

// VTP es el modo y el dominio de `show vtp status` (Mode en minúsculas: server, client, transparent, off;
// en v3 también "primary server" o "secondary server"). Version es "VTP version running" ("1", "2", "3").
// Ambiguous: la salida trae varios modos y no se pudo saber cuál es el de VLAN.
type VTP struct {
	Mode, Domain, Version string
	Ambiguous             bool
}

// ParseVTP lee `show vtp status`; ok=false si no trae el modo de operación. En v3 el modo sale una vez
// por función (VLAN, MST, UNKNOWN): se toma el de `Feature VLAN:`; sin esa sección, el de la primera línea
// (y si hay más de un modo, Ambiguous).
func ParseVTP(text string) (VTP, bool) {
	var v VTP
	var first, vlan string
	modes, inVLAN, hasVLAN := 0, false, false
	for _, l := range lines(text) {
		if t := strings.ToLower(strings.TrimSpace(l)); strings.HasPrefix(t, "feature ") && strings.HasSuffix(t, ":") {
			inVLAN = t == "feature vlan:"
			hasVLAN = hasVLAN || inVLAN
			continue
		}
		k, val, found := strings.Cut(l, ":")
		if !found {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "vtp operating mode":
			modes++
			if modes == 1 {
				first = strings.ToLower(val)
			}
			if inVLAN && vlan == "" {
				vlan = strings.ToLower(val)
			}
		case "vtp domain name":
			v.Domain = val
		case "vtp version running":
			v.Version = val
		}
	}
	v.Mode = first
	if hasVLAN {
		v.Mode = vlan
	}
	v.Ambiguous = modes > 1 && !hasVLAN
	return v, modes > 0 && v.Mode != ""
}

// UserLine es una línea `username ...` del running-config.
type UserLine struct {
	Name, Privilege string
	Kind            string // "secret" o "password"; vacío si no trae ninguno
	Type            string // 0, 5, 7, 8 o 9; vacío si la línea no lo dice
	Hash            string
	NoPassword      bool
	Extra           []string // tokens que no son `privilege N` ni `secret|password [tipo] valor` (view, autocommand, algorithm-type...)
	Raw             string
}

// ParseUsernames lee las líneas `username` de `show running-config | include ^username`.
func ParseUsernames(text string) []UserLine {
	var out []UserLine
	for _, l := range lines(text) {
		f := strings.Fields(strings.TrimSpace(l))
		if len(f) < 2 || f[0] != "username" {
			continue
		}
		u := UserLine{Name: f[1], Raw: strings.Join(f, " ")}
		for i := 2; i < len(f); i++ {
			switch f[i] {
			case "privilege":
				if i+1 < len(f) {
					u.Privilege = f[i+1]
					i++
				} else {
					u.Extra = append(u.Extra, f[i])
				}
			case "nopassword":
				u.NoPassword = true
			case "secret", "password":
				if u.Kind != "" || i+1 >= len(f) {
					u.Extra = append(u.Extra, f[i:]...)
					i = len(f)
					break
				}
				u.Kind = f[i]
				if rest := f[i+1:]; len(rest) >= 2 && len(rest[0]) == 1 && rest[0][0] >= '0' && rest[0][0] <= '9' {
					u.Type, u.Hash = rest[0], rest[1]
					i += 2
				} else {
					u.Hash = rest[0]
					i++
				}
			default:
				u.Extra = append(u.Extra, f[i])
			}
		}
		out = append(out, u)
	}
	return out
}

// TrunkAllowedSet evalúa las líneas `switchport trunk allowed vlan ...` de un trunk, en el orden en
// que IOS las imprime (la primera es la lista; las siguientes son add/remove). all=true si quedan
// permitidas las 4094 VLAN (sin línea, o all); si no, set son las permitidas.
func TrunkAllowedSet(lines []string) (set map[int]bool, all bool) {
	var on [4095]bool
	fill := func(v bool) {
		for i := 1; i <= 4094; i++ {
			on[i] = v
		}
	}
	fill(true)
	for _, l := range lines {
		f := strings.Fields(strings.ToLower(l))
		if len(f) < 5 {
			continue
		}
		switch args := f[4:]; {
		case args[0] == "add" && len(args) > 1:
			for _, id := range vlanList(args[1]) {
				on[id] = true
			}
		case args[0] == "remove" && len(args) > 1:
			for _, id := range vlanList(args[1]) {
				on[id] = false
			}
		case args[0] == "all":
			fill(true)
		case args[0] == "none":
			fill(false)
		case args[0] == "except" && len(args) > 1:
			fill(true)
			for _, id := range vlanList(args[1]) {
				on[id] = false
			}
		default:
			fill(false)
			for _, id := range vlanList(args[0]) {
				on[id] = true
			}
		}
	}
	set, all = map[int]bool{}, true
	for i := 1; i <= 4094; i++ {
		if on[i] {
			set[i] = true
		} else {
			all = false
		}
	}
	return set, all
}

// vlanList expande "1,10,20-22" en VLAN; ignora lo que no sea número o rango.
func vlanList(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		a, b, rng := strings.Cut(p, "-")
		lo, err := strconv.Atoi(a)
		if err != nil {
			continue
		}
		hi := lo
		if rng {
			if hi, err = strconv.Atoi(b); err != nil {
				continue
			}
		}
		for i := lo; i <= hi && i <= 4094; i++ {
			out = append(out, i)
		}
	}
	return out
}
