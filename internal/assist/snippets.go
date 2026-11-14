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

func refuseSnippet(code string, kv ...any) error {
	t := i18n.Tx(code, kv...)
	return &SnippetRefusal{Detail: t.In(i18n.Es), Why: t}
}

// SnippetRefusal es ErrSnippetRefused con su motivo. Template (id de la plantilla del catálogo) y Device los llena el
// servicio, que los conoce. Detail es el motivo en es; Why es el mismo motivo como código del catálogo, para darlo en el otro idioma.
type SnippetRefusal struct {
	Detail, Template, Device string
	Why                      i18n.Text
}

func (e *SnippetRefusal) Error() string        { return ErrSnippetRefused.Error() + ": " + e.Detail }
func (e *SnippetRefusal) Is(target error) bool { return target == ErrSnippetRefused }
func (e *SnippetRefusal) Reason() string       { return "assist.refused" }
func (e *SnippetRefusal) Localize(loc string) string {
	if e.Why.Empty() {
		return i18n.Msg(loc, "assist.refused", i18n.A("detail", e.Detail))
	}
	return i18n.Msg(loc, "assist.refused", i18n.A("detail", e.Why.In(loc)))
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
		return cerr("assist.err.vlan_range_reserved", "id", id)
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
			return "", "", lerr("VLAN no numérica", "non-numeric VLAN")
		}
		if e = vlanIDOK(id); e != nil {
			return "", "", e
		}
		return strings.Join(f[:len(f)-1], " "), a, nil
	case len(f) == 2 && f[0] == "name":
		n := strings.Fields(line)[1] // el nombre conserva las mayúsculas
		if !vlanNameRe.MatchString(n) {
			return "", "", lerr("nombre de VLAN inválido (letras, números, _ . -; hasta 32)", "invalid VLAN name (letters, numbers, _ . -; up to 32)")
		}
		return "name", n, nil
	}
	return "", "", lerr("no reconocida", "not recognized")
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
				return lerr("el apply de una VLAN es `vlan N` y, si se nombra, `name X`", "the apply of a VLAN is `vlan N` and, if it is named, `name X`")
			}
		}
		if applyID == "" {
			return lerr("el apply no empieza con `vlan N`", "the apply does not start with `vlan N`")
		}
		verb, arg, _ := parseVlanLine(strings.Join(d.Rollback[:min(1, len(d.Rollback))], ""))
		switch {
		case verb == "no vlan" && len(d.Rollback) == 1 && arg == applyID: // borra exactamente la VLAN creada
		case verb == "vlan" && len(d.Rollback) == 2 && arg == applyID:
			if v2, _, _ := parseVlanLine(d.Rollback[1]); v2 != "name" {
				return lerr("la reversa que conserva la VLAN restaura su nombre", "the rollback that keeps the VLAN restores its name")
			}
		default:
			return lerr("la reversa debe borrar solo la VLAN %s o restaurar su nombre", "the rollback must delete only VLAN %s or restore its name", applyID)
		}
		return nil
	},
}

// checkVlanDelete valida el borrado: un solo `no vlan N`, una reversa que recrea esa misma VLAN (y su nombre si lo
// tenía) y una verificación de que dejó de existir.
func checkVlanDelete(d DevicePlan, id string) error {
	if len(d.Apply) != 1 || len(d.Rollback) == 0 {
		return lerr("el apply de un borrado es solo `no vlan N`", "the apply of a deletion is only `no vlan N`")
	}
	if v, a, _ := parseVlanLine(d.Rollback[0]); v != "vlan" || a != id || len(d.Rollback) > 2 {
		return lerr("la reversa de borrar la VLAN %s es recrearla con `vlan %s` y su nombre", "the rollback of deleting VLAN %s is to recreate it with `vlan %s` and its name", id, id)
	}
	if len(d.Rollback) == 2 {
		if v, _, _ := parseVlanLine(d.Rollback[1]); v != "name" {
			return lerr("la reversa que recrea la VLAN solo restaura su nombre", "the rollback that recreates the VLAN only restores its name")
		}
	}
	for _, e := range d.Expect {
		if e.Column == "vlan-id" && !e.Present && e.Line == id {
			return nil
		}
	}
	return lerr("borrar la VLAN %s exige verificar que ya no existe", "deleting VLAN %s requires verifying that it no longer exists", id)
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
		return lerr("--remove no lleva nombre: borra la VLAN completa", "--remove takes no name: it deletes the whole VLAN")
	}
	if c.Name != "" && !vlanNameRe.MatchString(c.Name) {
		return lerr("nombre de VLAN inválido (letras, números, _ . -; hasta 32; sin espacios)", "invalid VLAN name (letters, numbers, _ . -; up to 32; no spaces)")
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
		return refuseSnippet("assist.refused.no_se_pudo_leer_show2", "device", device, "id", id)
	}
	for _, i := range svis {
		if strings.EqualFold(i.Raw, "Vlan"+id) {
			return refuseSnippet("assist.refused.la_vlan_de_tiene_svi", "id", id, "device", device, "svi", id)
		}
	}
	var onTrunk []string
	if tout := outs[showTrunks()]; strings.TrimSpace(tout) != "" { // sin trunks IOS no imprime nada
		trs, ok1 := iosxe.ParseTrunks(tout)
		act, ok2 := iosxe.ParseTrunkActive(tout)
		if !ok1 || !ok2 {
			return refuseSnippet("assist.refused.no_se_pudo_leer_show3", "device", device, "id", id)
		}
		for _, t := range trs {
			if t.Native == id {
				return refuseSnippet("assist.refused.la_vlan_es_la_nativa", "id", id, "port", t.Port, "device", device)
			}
		}
		for _, t := range act {
			if t.Vlans[c.ID] {
				onTrunk = append(onTrunk, t.Port)
			}
		}
	}
	if len(cur.Ports) > 0 {
		return refuseSnippet("assist.refused.la_vlan_de_tiene_puertos", "id", id, "device", device, "ports", strings.Join(cur.Ports, ", "))
	}
	if len(onTrunk) > 0 && !c.AcceptTrunk {
		return refuseSnippet("assist.refused.la_vlan_de_viaja_por", "id", id, "device", device, "trunks", strings.Join(onTrunk, ", "))
	}
	if cur.Status != "active" {
		return refuseSnippet("assist.refused.la_vlan_de_esta_en", "id", id, "device", device, "status", cur.Status)
	}
	if d, ok := iosxe.ParseVlanDetail(outs[showVlan(c.ID)], c.ID); !ok {
		return refuseSnippet("assist.refused.no_se_pudo_leer_el", "id", id, "device", device)
	} else if d.Type != "enet" || d.MTU != 1500 || d.RSPAN || d.Private {
		return refuseSnippet("assist.refused.la_vlan_de_no_es", "id", id, "device", device, "type", d.Type, "mtu", d.MTU, "rspan", d.RSPAN, "private", d.Private)
	}
	if !vlanNameRe.MatchString(cur.Name) {
		return refuseSnippet("assist.refused.el_nombre_de_la_vlan", "cur", cur.Name, "id", id)
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
			return DevicePlan{}, cerr("assist.err.output_missing", "command", cmd)
		}
	}
	vtp, ok := iosxe.ParseVTP(outs[showVtp()])
	prop := strings.Contains(vtp.Mode, "server") || strings.Contains(vtp.Mode, "client") // también "primary server"
	// En v3 un modo ambiguo o desconocido no se arriesga: el de VLAN podría ser servidor.
	unclear := vtp.Version == "3" && (vtp.Ambiguous || !(prop || vtp.Mode == "transparent" || vtp.Mode == "off"))
	switch {
	case !ok || unclear:
		if !c.AcceptVTP {
			return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_con", "device", device)
		}
	case prop && vtp.Domain != "" && !c.AcceptVTP:
		return DevicePlan{}, refuseSnippet("assist.refused.es_vtp_del_dominio_el", "device", device, "mode", vtp.Mode, "domain", vtp.Domain)
	}
	rows, ok := iosxe.ParseVlanBrief(outs["show vlan brief"])
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_show4", "device", device)
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
		return DevicePlan{}, refuseSnippet("assist.refused.show_vlan_brief_y_show", "id", c.ID, "device", device)
	}
	dp := DevicePlan{Device: device, Pre: pre, Post: []string{showVlan(c.ID)}, Baseline: map[string]string{showVlan(c.ID): outs[showVlan(c.ID)]}}
	want := c.Name
	switch {
	case c.Remove && cur == nil:
		return DevicePlan{}, cerr("assist.err.vlan_missing_on_device", "id", c.ID, "device", device)
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
		return DevicePlan{}, cerr("assist.err.vlan_already_named", "id", c.ID, "cur", cur.Name)
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
		return "", 0, lerr("solo `switchport trunk allowed vlan add N` o `remove N` (una VLAN); la forma sin add/remove reemplaza la lista y está prohibida", "only `switchport trunk allowed vlan add N` or `remove N` (one VLAN); the form without add/remove replaces the list and is forbidden")
	}
	n, e := strconv.Atoi(f[5])
	if e != nil || ntoa(n) != f[5] || n < 1 || n > 4094 {
		return "", 0, lerr("VLAN %q fuera de 1-4094 (una sola, sin listas ni rangos)", "VLAN %q outside 1-4094 (a single one, no lists or ranges)", f[5])
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
				return lerr("solo un puerto físico o un Port-channel", "only a physical port or a Port-channel")
			}
			return nil
		}
		_, _, err := trunkLine(line)
		return err
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) != 2 || len(d.Rollback) != 2 {
			return lerr("el apply y la reversa son una interfaz y una sola línea de trunk", "the apply and the rollback are one interface and a single trunk line")
		}
		if !strings.EqualFold(d.Apply[0], d.Rollback[0]) || !strings.HasPrefix(strings.ToLower(d.Apply[0]), "interface ") {
			return lerr("el apply y la reversa deben ser sobre la misma interfaz", "the apply and the rollback must be on the same interface")
		}
		op1, v1, err1 := trunkLine(d.Apply[1])
		op2, v2, err2 := trunkLine(d.Rollback[1])
		switch {
		case err1 != nil || err2 != nil:
			return lerr("el apply y la reversa llevan una línea add/remove", "the apply and the rollback carry an add/remove line")
		case v1 != v2 || op1 == op2:
			return lerr("la reversa debe ser la operación inversa sobre la misma VLAN", "the rollback must be the inverse operation on the same VLAN")
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
		return lerr("%q no es un puerto físico ni un Port-channel", "%q is neither a physical port nor a Port-channel", c.Interface)
	case c.Op != "add" && c.Op != "remove":
		return lerr("la operación es add o remove (nunca reemplazar la lista)", "the operation is add or remove (never replace the list)")
	case c.Vlan < 1 || c.Vlan > 4094:
		return lerr("VLAN %d fuera de 1-4094", "VLAN %d outside 1-4094", c.Vlan)
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
		return DevicePlan{}, cerr("assist.err.capture_missing", "port", c.Interface)
	}
	cur, ok := iosxe.ParseInterfaceConfig(text)
	if !ok || !strings.EqualFold(iosxe.ShortIf(cur.Name), iosxe.ShortIf(c.Interface)) {
		return DevicePlan{}, cerr("assist.err.capture_mismatch", "port", c.Interface)
	}
	swMode, _ := iosxe.ParseSwitchportMode(outs[showSwitchport(c.Interface)])
	switch {
	case cur.Routed || cur.L3:
		return DevicePlan{}, refuseSnippet("assist.refused.es_un_puerto_ruteado_o2", "interface", c.Interface)
	case cur.ChannelGroup:
		return DevicePlan{}, refuseSnippet("assist.refused.es_miembro_de_un_canal3", "interface", c.Interface)
	case cur.Mode == "access" || !(cur.Mode == "trunk" || swMode == "trunk"):
		return DevicePlan{}, refuseSnippet("assist.refused.no_es_un_trunk_ni", "interface", c.Interface)
	}
	set, all := iosxe.TrunkAllowedSet(cur.TrunkAllowed)
	allowed := all || set[c.Vlan]
	switch {
	case c.Op == "add" && allowed:
		return DevicePlan{}, cerr("assist.err.vlan_already_allowed", "vlan", c.Vlan, "interface", c.Interface)
	case c.Op == "remove" && !allowed:
		return DevicePlan{}, cerr("assist.err.vlan_not_allowed", "vlan", c.Vlan, "interface", c.Interface)
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
		return netip.Addr{}, 0, cerr("assist.err.mask_invalid")
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	ones := 0
	for ones < 32 && v&(1<<(31-ones)) != 0 {
		ones++
	}
	if ones < 8 || ones > 30 || v<<ones != 0 {
		return netip.Addr{}, 0, cerr("assist.err.mask_not_contiguous")
	}
	return a, ones, nil
}

// checkAddress valida la dirección de una SVI: IPv4 unicast, máscara contigua, ni red ni difusión.
func checkAddress(addr, mask string) error {
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() || strings.ContainsAny(addr, "/% ") {
		return cerr("assist.err.ipv4_invalid", "addr", addr)
	}
	if _, ones, err := parseMask(mask); err != nil {
		return err
	} else if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return cerr("assist.err.unicast_invalid", "addr", addr)
	} else if p, _ := a.Prefix(ones); p.Addr() == a || lastOf(p) == a {
		return cerr("assist.err.network_or_broadcast", "addr", addr, "ones", ones)
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
		return withPrefix("assist.err.description_invalid", err)
	}
	if strings.ContainsAny(d, "?\t") || len(strings.TrimSpace(d)) > 200 {
		return cerr("assist.err.description_rule")
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
				return cerr("assist.err.extra_arguments")
			}
			if _, ok := sviID(f[len(f)-1]); !ok {
				return cerr("assist.err.single_svi")
			}
		case strings.HasPrefix(l, "ip address "):
			if len(f) != 4 {
				return cerr("assist.err.ip_address_form")
			}
			return checkAddress(f[2], f[3])
		case l == "no ip address" || l == "shutdown" || l == "no shutdown" || l == "no description":
		case strings.HasPrefix(l, "description"):
			return descOK(strings.TrimSpace(line[len("description"):]))
		default:
			return cerr("assist.err.not_recognized")
		}
		return nil
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) == 0 || !strings.HasPrefix(strings.ToLower(d.Apply[0]), "interface ") {
			return cerr("assist.err.apply_starts_svi")
		}
		iface := strings.Fields(d.Apply[0])[1]
		for _, l := range d.Apply {
			if strings.HasPrefix(strings.ToLower(l), "no interface") || strings.HasPrefix(strings.ToLower(l), "no ip address") {
				return cerr("assist.err.apply_no_delete")
			}
			if strings.HasPrefix(strings.ToLower(l), "interface ") && !strings.EqualFold(strings.Fields(l)[1], iface) {
				return cerr("assist.err.apply_single_interface")
			}
		}
		if len(d.Rollback) == 0 {
			return nil
		}
		first := strings.Fields(d.Rollback[0])
		switch {
		case len(first) == 3 && strings.EqualFold(first[0], "no") && strings.EqualFold(first[1], "interface"):
			if len(d.Rollback) != 1 || !strings.EqualFold(first[2], iface) {
				return cerr("assist.err.no_interface_only", "iface", iface)
			}
		case len(first) == 2 && strings.EqualFold(first[0], "interface") && strings.EqualFold(first[1], iface):
			for _, l := range d.Rollback[1:] {
				if strings.HasPrefix(strings.ToLower(l), "interface") || strings.HasPrefix(strings.ToLower(l), "no interface") {
					return cerr("assist.err.rollback_single_interface")
				}
			}
		default:
			return cerr("assist.err.rollback_must_delete", "iface", iface)
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
		return lerr("VLAN %d fuera de 1-4094", "VLAN %d outside 1-4094", c.VlanID)
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
		return DevicePlan{}, cerr("assist.err.outputs_missing", "command1", pre[0], "command2", showIPBrief)
	}
	rows, ok := iosxe.ParseIPBrief(brief)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_show", "device", device)
	}
	inBrief := false
	for _, r := range rows {
		if strings.EqualFold(r.Iface, "Vl"+ntoa(c.VlanID)) || strings.EqualFold(r.Raw, name) {
			inBrief = true
		}
		if r.IP == c.Address {
			return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_la_direccion_asignada2", "device", device, "address", c.Address, "owner", r.Raw)
		}
	}
	cur, exists := iosxe.ParseInterfaceConfig(text)
	switch {
	case exists && !strings.EqualFold(cur.Name, name):
		return DevicePlan{}, refuseSnippet("assist.refused.la_captura_no_es_la", "name", name)
	case !exists && !strings.Contains(text, "% Invalid input") && !strings.Contains(text, "not found"):
		return DevicePlan{}, refuseSnippet("assist.refused.la_captura_de_no_es", "port", name)
	case exists != inBrief:
		return DevicePlan{}, refuseSnippet("assist.refused.la_configuracion_y_show_ip", "name", name, "device", device)
	case exists && (cur.L3 || cur.Routed):
		return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_direccion_ip_o", "name", name)
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
