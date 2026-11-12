package assist

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// ErrSnippetRefused: el equipo no está en un estado en que el snippet sea seguro (VTP que propaga, interfaz que no
// es trunk, SVI con IP, existencia dudosa...). Es una negativa, no un error de uso.
var ErrSnippetRefused = errors.New("assist: el equipo no admite este snippet")

func refuseSnippet(format string, a ...any) error {
	return &SnippetRefusal{Detail: fmt.Sprintf(format, a...)}
}

// SnippetRefusal es ErrSnippetRefused con su motivo. Template (nombre de la función del snippet) y Device los llena el
// servicio, que los conoce. Detail sigue en español hasta que se traduzcan los motivos de cada negativa.
type SnippetRefusal struct{ Detail, Template, Device string }

func (e *SnippetRefusal) Error() string       { return ErrSnippetRefused.Error() + ": " + e.Detail }
func (e *SnippetRefusal) Is(target error) bool { return target == ErrSnippetRefused }
func (e *SnippetRefusal) Reason() string       { return "assist.refused" }
func (e *SnippetRefusal) Localize(loc string) string {
	return i18n.Msg(loc, "assist.refused", i18n.A("detail", e.Detail))
}

// Metadata dice la plantilla y el equipo; el motivo (Detail) viaja solo en el mensaje.
func (e *SnippetRefusal) Metadata() map[string]string {
	return i18n.Metadata("assist.refused", i18n.A("template", e.Template, "device", e.Device))
}

func ntoa(n int) string { return strconv.Itoa(n) }

func showVtp() string { return "show vtp status" }

func showTrunks() string { return "show interfaces trunk" }

// ---- VLAN ----

var vlanNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

// vlanIDOK acepta 2-4094 salvo las reservadas 1002-1005 (IOS no deja crearlas ni borrarlas).
func vlanIDOK(id int) error {
	if id < 2 || id > 4094 || (id >= 1002 && id <= 1005) {
		return fmt.Errorf("VLAN %d fuera de 2-4094 o reservada (1, 1002-1005)", id)
	}
	return nil
}

func defaultVlanName(id int) string { return fmt.Sprintf("VLAN%04d", id) }

// parseVlanLine devuelve el verbo ("vlan", "name", "no vlan") y su argumento ya validado.
func parseVlanLine(line string) (verb, arg string, err error) {
	f := strings.Fields(strings.ToLower(line))
	switch {
	case len(f) == 2 && f[0] == "vlan", len(f) == 3 && f[0] == "no" && f[1] == "vlan":
		a := f[len(f)-1]
		id, e := strconv.Atoi(a)
		if e != nil || ntoa(id) != a {
			return "", "", errors.New("VLAN no numérica")
		}
		if e = vlanIDOK(id); e != nil {
			return "", "", e
		}
		return strings.Join(f[:len(f)-1], " "), a, nil
	case len(f) == 2 && f[0] == "name":
		n := strings.Fields(line)[1] // el nombre conserva las mayúsculas
		if !vlanNameRe.MatchString(n) {
			return "", "", errors.New("nombre de VLAN inválido (letras, números, _ . -; hasta 32)")
		}
		return "name", n, nil
	}
	return "", "", errors.New("no reconocida")
}

// SnippetVlan crea, nombra o borra una VLAN; al crear, la reversa borra solo la que el snippet creó; al borrar, la recrea con su nombre.
var SnippetVlan = Function{
	Name:    "snippet-vlan",
	Allowed: []string{"vlan", "name", "no vlan"},
	Check: func(line string) error {
		_, _, err := parseVlanLine(line)
		return err
	},
	CheckDevice: func(d DevicePlan) error {
		if verb, id, _ := parseVlanLine(strings.Join(d.Apply[:min(1, len(d.Apply))], "")); verb == "no vlan" {
			return checkVlanDelete(d, id)
		}
		var applyID string
		for i, l := range d.Apply {
			verb, arg, _ := parseVlanLine(l)
			switch {
			case i == 0 && verb == "vlan":
				applyID = arg
			case i == 1 && verb == "name" && len(d.Apply) == 2:
			default:
				return errors.New("el apply de una VLAN es `vlan N` y, si se nombra, `name X`")
			}
		}
		if applyID == "" {
			return errors.New("el apply no empieza con `vlan N`")
		}
		verb, arg, _ := parseVlanLine(strings.Join(d.Rollback[:min(1, len(d.Rollback))], ""))
		switch {
		case verb == "no vlan" && len(d.Rollback) == 1 && arg == applyID: // borra exactamente la VLAN creada
		case verb == "vlan" && len(d.Rollback) == 2 && arg == applyID:
			if v2, _, _ := parseVlanLine(d.Rollback[1]); v2 != "name" {
				return errors.New("la reversa que conserva la VLAN restaura su nombre")
			}
		default:
			return fmt.Errorf("la reversa debe borrar solo la VLAN %s o restaurar su nombre", applyID)
		}
		return nil
	},
}

// checkVlanDelete valida el borrado: un solo `no vlan N`, una reversa que recrea esa misma VLAN (y su nombre si lo
// tenía) y una verificación de que dejó de existir.
func checkVlanDelete(d DevicePlan, id string) error {
	if len(d.Apply) != 1 || len(d.Rollback) == 0 {
		return errors.New("el apply de un borrado es solo `no vlan N`")
	}
	if v, a, _ := parseVlanLine(d.Rollback[0]); v != "vlan" || a != id || len(d.Rollback) > 2 {
		return fmt.Errorf("la reversa de borrar la VLAN %s es recrearla con `vlan %s` y su nombre", id, id)
	}
	if len(d.Rollback) == 2 {
		if v, _, _ := parseVlanLine(d.Rollback[1]); v != "name" {
			return errors.New("la reversa que recrea la VLAN solo restaura su nombre")
		}
	}
	for _, e := range d.Expect {
		if e.Column == "vlan-id" && !e.Present && e.Line == id {
			return nil
		}
	}
	return fmt.Errorf("borrar la VLAN %s exige verificar que ya no existe", id)
}

// VlanChange: crear la VLAN ID, ponerle Name si ya existe, o borrarla (Remove, sin Name). AcceptVTP acepta que se propague por VTP.
type VlanChange struct {
	ID          int
	Name        string
	AcceptVTP   bool
	Remove      bool
	AcceptTrunk bool // solo al borrar: acepta que la VLAN viaje por trunks
}

func (c VlanChange) check() error {
	if err := vlanIDOK(c.ID); err != nil {
		return err
	}
	if c.Remove && c.Name != "" {
		return errors.New("--remove no lleva nombre: borra la VLAN completa")
	}
	if c.Name != "" && !vlanNameRe.MatchString(c.Name) {
		return errors.New("nombre de VLAN inválido (letras, números, _ . -; hasta 32; sin espacios)")
	}
	return nil
}

// VlanPre devuelve los comandos de lectura: la tabla de VLAN, el modo VTP y la VLAN pedida.
func VlanPre(c VlanChange) ([]string, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	pre := []string{"show vlan brief", showVtp(), showVlan(c.ID)}
	if c.Remove {
		// Para borrar también se lee quién más usa la VLAN: una SVI y los trunks no salen en show vlan brief.
		pre = append(pre, showIPBrief, showTrunks())
	}
	return pre, nil
}

// vlanRemoveBlockers revisa lo que impide borrar con seguridad la VLAN cur: su SVI (puede ser la gestión: el borrado
// cortaría la sesión y la reversa no llegaría), los trunks que la llevan, los puertos asignados, un estado o
// parámetros que la reversa no restauraría y un nombre que no se pueda reescribir.
func vlanRemoveBlockers(device string, c VlanChange, cur *iosxe.VlanRow, outs map[string]string) error {
	id := ntoa(c.ID)
	svis, ok := iosxe.ParseIPBrief(outs[showIPBrief])
	if !ok {
		return refuseSnippet("no se pudo leer show ip interface brief de %s: sin saber si la VLAN %s tiene SVI no se borra", device, id)
	}
	for _, i := range svis {
		if strings.EqualFold(i.Raw, "Vlan"+id) {
			return refuseSnippet("la VLAN %s de %s tiene SVI (interface Vlan%s): quítala primero; si es la de gestión, borrar la VLAN cortaría tu sesión", id, device, id)
		}
	}
	var onTrunk []string
	if tout := outs[showTrunks()]; strings.TrimSpace(tout) != "" { // sin trunks IOS no imprime nada
		trs, ok1 := iosxe.ParseTrunks(tout)
		act, ok2 := iosxe.ParseTrunkActive(tout)
		if !ok1 || !ok2 {
			return refuseSnippet("no se pudo leer show interfaces trunk de %s: sin saber si la VLAN %s viaja por un trunk no se borra", device, id)
		}
		for _, t := range trs {
			if t.Native == id {
				return refuseSnippet("la VLAN %s es la nativa del trunk %s de %s: no se borra", id, t.Port, device)
			}
		}
		for _, t := range act {
			if t.Vlans[c.ID] {
				onTrunk = append(onTrunk, t.Port)
			}
		}
	}
	if len(cur.Ports) > 0 {
		return refuseSnippet("la VLAN %s de %s tiene puertos asignados (%s): muévelos a otra VLAN antes, porque borrarla los dejaría inactivos", id, device, strings.Join(cur.Ports, ", "))
	}
	if len(onTrunk) > 0 && !c.AcceptTrunk {
		return refuseSnippet("la VLAN %s de %s viaja por los trunks %s: borrarla corta su tráfico (acéptalo de forma explícita si es lo que quieres)", id, device, strings.Join(onTrunk, ", "))
	}
	if cur.Status != "active" {
		return refuseSnippet("la VLAN %s de %s está en estado %q, no activa: la reversa no podría restaurarla igual", id, device, cur.Status)
	}
	if d, ok := iosxe.ParseVlanDetail(outs[showVlan(c.ID)], c.ID); !ok {
		return refuseSnippet("no se pudo leer el tipo y el MTU de la VLAN %s en %s: la reversa no puede garantizar restaurarla igual", id, device)
	} else if d.Type != "enet" || d.MTU != 1500 || d.RSPAN || d.Private {
		return refuseSnippet("la VLAN %s de %s no es una VLAN Ethernet común (tipo %s, MTU %d, Remote SPAN %v, privada %v): la reversa no podría restaurarla igual", id, device, d.Type, d.MTU, d.RSPAN, d.Private)
	}
	if !vlanNameRe.MatchString(cur.Name) {
		return refuseSnippet("el nombre %q de la VLAN %s no se puede restaurar con la reversa", cur.Name, id)
	}
	return nil
}

// VlanPlan arma el plan: si la VLAN no existía la reversa la borra; si existía restaura su nombre (nunca la borra).
// Un equipo con VTP servidor o cliente propagaría el cambio a todo el dominio: se rechaza salvo AcceptVTP.
func VlanPlan(device string, c VlanChange, outs map[string]string) (DevicePlan, error) {
	pre, err := VlanPre(c)
	if err != nil {
		return DevicePlan{}, err
	}
	for _, cmd := range pre {
		if _, ok := outs[cmd]; !ok {
			return DevicePlan{}, fmt.Errorf("falta la salida de %q", cmd)
		}
	}
	vtp, ok := iosxe.ParseVTP(outs[showVtp()])
	prop := strings.Contains(vtp.Mode, "server") || strings.Contains(vtp.Mode, "client") // también "primary server"
	// En v3 un modo ambiguo o desconocido no se arriesga: el de VLAN podría ser servidor.
	unclear := vtp.Version == "3" && (vtp.Ambiguous || !(prop || vtp.Mode == "transparent" || vtp.Mode == "off"))
	switch {
	case !ok || unclear:
		if !c.AcceptVTP {
			return DevicePlan{}, refuseSnippet("no se pudo leer con certeza el modo VTP de %s: con VTP servidor o cliente el cambio se propagaría al dominio", device)
		}
	case prop && vtp.Domain != "" && !c.AcceptVTP:
		return DevicePlan{}, refuseSnippet("%s es VTP %s del dominio %q: el cambio se propagaría a todo el dominio (acéptalo de forma explícita si es lo que quieres)", device, vtp.Mode, vtp.Domain)
	}
	rows, ok := iosxe.ParseVlanBrief(outs["show vlan brief"])
	if !ok {
		return DevicePlan{}, refuseSnippet("no se pudo leer show vlan brief de %s", device)
	}
	var cur *iosxe.VlanRow
	for i := range rows {
		if rows[i].ID == c.ID {
			cur = &rows[i]
		}
	}
	// La reversa borra la VLAN si "no existía": ese dato se confirma con un segundo comando.
	byID, idOK := iosxe.ParseVlanBrief(outs[showVlan(c.ID)])
	if (cur != nil) != (idOK && len(byID) > 0) {
		return DevicePlan{}, refuseSnippet("show vlan brief y show vlan id %d no coinciden sobre si la VLAN existe en %s", c.ID, device)
	}
	dp := DevicePlan{Device: device, Pre: pre, Post: []string{showVlan(c.ID)}, Baseline: map[string]string{showVlan(c.ID): outs[showVlan(c.ID)]}}
	want := c.Name
	switch {
	case c.Remove && cur == nil:
		return DevicePlan{}, fmt.Errorf("la VLAN %d no existe en %s", c.ID, device)
	case c.Remove:
		if err := vlanRemoveBlockers(device, c, cur, outs); err != nil {
			return DevicePlan{}, err
		}
		dp.Apply = []string{"no vlan " + ntoa(c.ID)}
		dp.Rollback = []string{"vlan " + ntoa(c.ID)}
		if cur.Name != defaultVlanName(c.ID) {
			dp.Rollback = append(dp.Rollback, "name "+cur.Name)
		}
		want = cur.Name
	case cur == nil:
		dp.Apply = []string{"vlan " + ntoa(c.ID)}
		if c.Name != "" {
			dp.Apply = append(dp.Apply, "name "+c.Name)
		} else {
			want = defaultVlanName(c.ID)
		}
		dp.Rollback = []string{"no vlan " + ntoa(c.ID)}
	case c.Name == "" || c.Name == cur.Name:
		return DevicePlan{}, fmt.Errorf("la VLAN %d ya existe con ese nombre (%s): no hay nada que cambiar", c.ID, cur.Name)
	default:
		dp.Apply = []string{"vlan " + ntoa(c.ID), "name " + c.Name}
		dp.Rollback = []string{"vlan " + ntoa(c.ID), "name " + cur.Name}
	}
	dp.Expect = []Expect{{Command: showVlan(c.ID), Line: ntoa(c.ID) + " " + want, Present: true, Column: "vlan"}}
	if c.Remove {
		// Borrada = ninguna fila con ese ID, sea cual sea su nombre o estado.
		dp.Expect = []Expect{{Command: showVlan(c.ID), Line: ntoa(c.ID), Present: false, Column: "vlan-id"}}
	}
	if err := Validate(Plan{Function: SnippetVlan.Name, Devices: []DevicePlan{dp}}, SnippetVlan); err != nil {
		return DevicePlan{}, err
	}
	return dp, nil
}

// ---- Trunk ----

var poRe = regexp.MustCompile(`(?i)^(port-channel|po)\d+$`)

// ValidTrunkInterface: un puerto físico o un Port-channel (el trunk de subida suele ser un canal).
func ValidTrunkInterface(n string) bool { return ValidInterface(n) || poRe.MatchString(n) }

// trunkLine devuelve (op, vlan) de `switchport trunk allowed vlan add|remove N`. Cualquier otra forma
// de esa línea (sin add/remove, listas, rangos, all, none, except) es un error: reemplaza la lista y es la causa
// clásica de caídas.
func trunkLine(line string) (op string, vlan int, err error) {
	f := strings.Fields(strings.ToLower(line))
	if len(f) != 6 || (f[4] != "add" && f[4] != "remove") {
		return "", 0, errors.New("solo `switchport trunk allowed vlan add N` o `remove N` (una VLAN); la forma sin add/remove reemplaza la lista y está prohibida")
	}
	n, e := strconv.Atoi(f[5])
	if e != nil || ntoa(n) != f[5] || n < 1 || n > 4094 {
		return "", 0, fmt.Errorf("VLAN %q fuera de 1-4094 (una sola, sin listas ni rangos)", f[5])
	}
	return f[4], n, nil
}

// SnippetTrunk agrega o quita una VLAN de un trunk, siempre con add o remove.
var SnippetTrunk = Function{
	Name:    "snippet-trunk",
	Allowed: []string{"interface", "switchport trunk allowed vlan"},
	Check: func(line string) error {
		f := strings.Fields(line)
		if strings.EqualFold(f[0], "interface") {
			if len(f) != 2 || !ValidTrunkInterface(f[1]) {
				return errors.New("solo un puerto físico o un Port-channel")
			}
			return nil
		}
		_, _, err := trunkLine(line)
		return err
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) != 2 || len(d.Rollback) != 2 {
			return errors.New("el apply y la reversa son una interfaz y una sola línea de trunk")
		}
		if !strings.EqualFold(d.Apply[0], d.Rollback[0]) || !strings.HasPrefix(strings.ToLower(d.Apply[0]), "interface ") {
			return errors.New("el apply y la reversa deben ser sobre la misma interfaz")
		}
		op1, v1, err1 := trunkLine(d.Apply[1])
		op2, v2, err2 := trunkLine(d.Rollback[1])
		switch {
		case err1 != nil || err2 != nil:
			return errors.New("el apply y la reversa llevan una línea add/remove")
		case v1 != v2 || op1 == op2:
			return errors.New("la reversa debe ser la operación inversa sobre la misma VLAN")
		}
		return nil
	},
}

// TrunkChange: agregar (Op "add") o quitar ("remove") la VLAN Vlan de la lista permitida de Interface.
type TrunkChange struct {
	Interface, Op string
	Vlan          int
}

func (c TrunkChange) check() error {
	switch {
	case !ValidTrunkInterface(c.Interface):
		return fmt.Errorf("%q no es un puerto físico ni un Port-channel", c.Interface)
	case c.Op != "add" && c.Op != "remove":
		return errors.New("la operación es add o remove (nunca reemplazar la lista)")
	case c.Vlan < 1 || c.Vlan > 4094:
		return fmt.Errorf("VLAN %d fuera de 1-4094", c.Vlan)
	}
	return nil
}

// TrunkPre: la configuración de la interfaz y su modo de switchport.
func TrunkPre(c TrunkChange) ([]string, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	return []string{showCfg(c.Interface), showSwitchport(c.Interface)}, nil
}

// TrunkPlan arma el plan de un trunk. Se rechaza si la interfaz no es trunk, si es miembro de un canal o ruteada, y si el cambio
// no cambia nada (add de una VLAN ya permitida, remove de una que no lo está: la reversa quitaría o pondría algo que ya estaba).
func TrunkPlan(device string, c TrunkChange, outs map[string]string) (DevicePlan, error) {
	pre, err := TrunkPre(c)
	if err != nil {
		return DevicePlan{}, err
	}
	text, ok := outs[showCfg(c.Interface)]
	if !ok {
		return DevicePlan{}, fmt.Errorf("falta la configuración capturada de %s", c.Interface)
	}
	cur, ok := iosxe.ParseInterfaceConfig(text)
	if !ok || !strings.EqualFold(iosxe.ShortIf(cur.Name), iosxe.ShortIf(c.Interface)) {
		return DevicePlan{}, fmt.Errorf("la captura de %s no es la configuración de esa interfaz", c.Interface)
	}
	swMode, _ := iosxe.ParseSwitchportMode(outs[showSwitchport(c.Interface)])
	switch {
	case cur.Routed || cur.L3:
		return DevicePlan{}, refuseSnippet("%s es un puerto ruteado o de capa 3", c.Interface)
	case cur.ChannelGroup:
		return DevicePlan{}, refuseSnippet("%s es miembro de un canal: cambia el Port-channel, no el miembro", c.Interface)
	case cur.Mode == "access" || !(cur.Mode == "trunk" || swMode == "trunk"):
		return DevicePlan{}, refuseSnippet("%s no es un trunk (ni switchport mode trunk ni Administrative Mode: trunk)", c.Interface)
	}
	set, all := iosxe.TrunkAllowedSet(cur.TrunkAllowed)
	allowed := all || set[c.Vlan]
	switch {
	case c.Op == "add" && allowed:
		return DevicePlan{}, fmt.Errorf("la VLAN %d ya está permitida en %s: no hay nada que cambiar", c.Vlan, c.Interface)
	case c.Op == "remove" && !allowed:
		return DevicePlan{}, fmt.Errorf("la VLAN %d no está permitida en %s: no hay nada que cambiar", c.Vlan, c.Interface)
	}
	inverse := map[string]string{"add": "remove", "remove": "add"}[c.Op]
	line := func(op string) string { return fmt.Sprintf("switchport trunk allowed vlan %s %d", op, c.Vlan) }
	dp := DevicePlan{Device: device, Pre: pre,
		Apply:    []string{"interface " + c.Interface, line(c.Op)},
		Rollback: []string{"interface " + c.Interface, line(inverse)},
		Post:     []string{showCfg(c.Interface)}, Baseline: map[string]string{showCfg(c.Interface): text},
		Expect: []Expect{{Command: showCfg(c.Interface), Line: ntoa(c.Vlan), Present: c.Op == "add", Column: "trunk-allowed"}}}
	if err := Validate(Plan{Function: SnippetTrunk.Name, Devices: []DevicePlan{dp}}, SnippetTrunk); err != nil {
		return DevicePlan{}, err
	}
	return dp, nil
}

// ---- SVI ----

var sviNameRe = regexp.MustCompile(`(?i)^vlan(\d{1,4})$`)

func sviID(name string) (int, bool) {
	m := sviNameRe.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	n, _ := strconv.Atoi(m[1])
	return n, n >= 1 && n <= 4094 && ntoa(n) == m[1]
}

// parseMask lee una máscara decimal con puntos contigua de /8 a /30.
func parseMask(m string) (netip.Addr, int, error) {
	a, err := netip.ParseAddr(m)
	if err != nil || !a.Is4() {
		return netip.Addr{}, 0, errors.New("máscara inválida (usa la forma 255.255.255.0)")
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	ones := 0
	for ones < 32 && v&(1<<(31-ones)) != 0 {
		ones++
	}
	if ones < 8 || ones > 30 || v<<ones != 0 {
		return netip.Addr{}, 0, errors.New("máscara no contigua o fuera de /8-/30")
	}
	return a, ones, nil
}

// checkAddress valida la dirección de una SVI: IPv4 unicast, máscara contigua, ni red ni difusión.
func checkAddress(addr, mask string) error {
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() || strings.ContainsAny(addr, "/% ") {
		return fmt.Errorf("dirección IPv4 inválida %q", addr)
	}
	if _, ones, err := parseMask(mask); err != nil {
		return err
	} else if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return fmt.Errorf("%s no es una dirección unicast válida", addr)
	} else if p, _ := a.Prefix(ones); p.Addr() == a || lastOf(p) == a {
		return fmt.Errorf("%s es la dirección de red o de difusión de /%d", addr, ones)
	}
	return nil
}

func lastOf(p netip.Prefix) netip.Addr {
	b := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := (uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func descOK(d string) error {
	if err := asciiOnly(d); err != nil {
		return fmt.Errorf("descripción: %w", err)
	}
	if strings.ContainsAny(d, "?\t") || len(strings.TrimSpace(d)) > 200 {
		return errors.New("la descripción no admite '?' y mide como máximo 200 caracteres")
	}
	return nil
}

// SnippetSVI crea la interfaz VLAN con descripción, IP y no shutdown.
var SnippetSVI = Function{
	Name:    "snippet-svi",
	Allowed: []string{"interface", "no interface", "description", "no description", "ip address", "no ip address", "shutdown", "no shutdown"},
	Check: func(line string) error {
		f := strings.Fields(line)
		l := strings.ToLower(line)
		switch {
		case strings.EqualFold(f[0], "interface"), strings.HasPrefix(l, "no interface "):
			if len(f) != map[bool]int{true: 2, false: 3}[strings.EqualFold(f[0], "interface")] {
				return errors.New("sobran argumentos")
			}
			if _, ok := sviID(f[len(f)-1]); !ok {
				return errors.New("solo una interfaz VlanN")
			}
		case strings.HasPrefix(l, "ip address "):
			if len(f) != 4 {
				return errors.New("`ip address A M`, sin secundarias ni otras formas")
			}
			return checkAddress(f[2], f[3])
		case l == "no ip address" || l == "shutdown" || l == "no shutdown" || l == "no description":
		case strings.HasPrefix(l, "description"):
			return descOK(strings.TrimSpace(line[len("description"):]))
		default:
			return errors.New("no reconocida")
		}
		return nil
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) == 0 || !strings.HasPrefix(strings.ToLower(d.Apply[0]), "interface ") {
			return errors.New("el apply empieza con `interface VlanN`")
		}
		iface := strings.Fields(d.Apply[0])[1]
		for _, l := range d.Apply {
			if strings.HasPrefix(strings.ToLower(l), "no interface") || strings.HasPrefix(strings.ToLower(l), "no ip address") {
				return errors.New("el apply no borra interfaces ni direcciones")
			}
			if strings.HasPrefix(strings.ToLower(l), "interface ") && !strings.EqualFold(strings.Fields(l)[1], iface) {
				return errors.New("el apply toca una sola interfaz")
			}
		}
		if len(d.Rollback) == 0 {
			return nil
		}
		first := strings.Fields(d.Rollback[0])
		switch {
		case len(first) == 3 && strings.EqualFold(first[0], "no") && strings.EqualFold(first[1], "interface"):
			if len(d.Rollback) != 1 || !strings.EqualFold(first[2], iface) {
				return fmt.Errorf("`no interface` solo puede borrar %s, la interfaz que el apply crea", iface)
			}
		case len(first) == 2 && strings.EqualFold(first[0], "interface") && strings.EqualFold(first[1], iface):
			for _, l := range d.Rollback[1:] {
				if strings.HasPrefix(strings.ToLower(l), "interface") || strings.HasPrefix(strings.ToLower(l), "no interface") {
					return errors.New("la reversa restaura una sola interfaz")
				}
			}
		default:
			return fmt.Errorf("la reversa debe borrar %s o restaurarla", iface)
		}
		return nil
	},
}

// SVIChange: crear la interfaz Vlan<VlanID> con Address y Mask; Description nil = sin descripción.
type SVIChange struct {
	VlanID        int
	Description   *string
	Address, Mask string
}

func (c SVIChange) check() error {
	if c.VlanID < 1 || c.VlanID > 4094 {
		return fmt.Errorf("VLAN %d fuera de 1-4094", c.VlanID)
	}
	if err := checkAddress(c.Address, c.Mask); err != nil {
		return err
	}
	if c.Description != nil {
		return descOK(*c.Description)
	}
	return nil
}

const showIPBrief = "show ip interface brief"

// SVIPre: la configuración de la SVI y la tabla de interfaces con IP (existencia y direcciones repetidas).
func SVIPre(c SVIChange) ([]string, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	return []string{showCfg("Vlan" + ntoa(c.VlanID)), showIPBrief}, nil
}

// SVIPlan arma el plan. La reversa es `no interface VlanN` solo si la SVI no existía, y eso se confirma con dos comandos
// distintos (la configuración y show ip interface brief): si no coinciden se rechaza, porque borrar una SVI ajena corta el equipo.
func SVIPlan(device string, c SVIChange, outs map[string]string) (DevicePlan, error) {
	pre, err := SVIPre(c)
	if err != nil {
		return DevicePlan{}, err
	}
	name := "Vlan" + ntoa(c.VlanID)
	text, ok := outs[pre[0]]
	brief, ok2 := outs[showIPBrief]
	if !ok || !ok2 {
		return DevicePlan{}, fmt.Errorf("faltan las salidas de %q y %q", pre[0], showIPBrief)
	}
	rows, ok := iosxe.ParseIPBrief(brief)
	if !ok {
		return DevicePlan{}, refuseSnippet("no se pudo leer show ip interface brief de %s", device)
	}
	inBrief := false
	for _, r := range rows {
		if strings.EqualFold(r.Iface, "Vl"+ntoa(c.VlanID)) || strings.EqualFold(r.Raw, name) {
			inBrief = true
		}
		if r.IP == c.Address {
			return DevicePlan{}, refuseSnippet("%s ya tiene la dirección %s asignada a %s", device, c.Address, r.Raw)
		}
	}
	cur, exists := iosxe.ParseInterfaceConfig(text)
	switch {
	case exists && !strings.EqualFold(cur.Name, name):
		return DevicePlan{}, refuseSnippet("la captura no es la configuración de %s", name)
	case !exists && !strings.Contains(text, "% Invalid input") && !strings.Contains(text, "not found"):
		return DevicePlan{}, refuseSnippet("la captura de %s no es una interfaz ni el aviso de IOS de que no existe", name)
	case exists != inBrief:
		return DevicePlan{}, refuseSnippet("la configuración y show ip interface brief no coinciden sobre si %s existe en %s", name, device)
	case exists && (cur.L3 || cur.Routed):
		return DevicePlan{}, refuseSnippet("%s ya tiene dirección IP (o VRF/NAT): no se sobrescribe", name)
	}
	dp := DevicePlan{Device: device, Pre: pre, Post: []string{showCfg(name)}, Baseline: map[string]string{showCfg(name): text}}
	dp.Apply = []string{"interface " + name}
	ex := func(l string, present bool) {
		dp.Expect = append(dp.Expect, Expect{Command: showCfg(name), Line: l, Present: present})
	}
	if c.Description != nil && strings.TrimSpace(*c.Description) != "" {
		d := strings.TrimSpace(*c.Description)
		dp.Apply = append(dp.Apply, "description "+d)
		ex("description "+d, true)
	}
	dp.Apply = append(dp.Apply, "ip address "+c.Address+" "+c.Mask, "no shutdown")
	ex("ip address "+c.Address+" "+c.Mask, true)
	ex("shutdown", false)
	if !exists {
		dp.Rollback = []string{"no interface " + name}
	} else {
		dp.Rollback = []string{"interface " + name, "no ip address",
			ifElse(cur.HasDescription, "description "+cur.Description, "no description"), ifElse(cur.Shutdown, "shutdown", "no shutdown")}
	}
	if err := Validate(Plan{Function: SnippetSVI.Name, Devices: []DevicePlan{dp}}, SnippetSVI); err != nil {
		return DevicePlan{}, err
	}
	return dp, nil
}
