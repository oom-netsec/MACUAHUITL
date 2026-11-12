package assist

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/iosconf"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Lista cerrada de restore-diff (ADR 0007). Solo estas familias de líneas se aplican, comparadas palabra por palabra:
//   - globales: hostname, logging, ntp server, snmp-server location|contact, ip domain-name|name-server, clock, service timestamps,
//     spanning-tree portfast default, errdisable recovery y, dentro de `vlan N` (que existe en los dos lados), name;
//   - en una interfaz física de acceso (switchport mode access en los dos lados, que no sea la de gestión ni lleve su VLAN):
//     description, switchport access|voice vlan, shutdown, spanning-tree portfast|bpduguard y storm-control (broadcast|multicast|unicast level, action).
//
// Todo lo demás se rechaza y se lista para hacerlo a mano. Las abreviaturas de IOS cuentan como la palabra completa (playbook.Abbrev) al
// decidir qué es una línea rechazada; en lo permitido se exige la palabra completa, que es como la imprime el running-config.

type word []string // prefijo de tokens, sin "no"

func tokens(s string) []string { return strings.Fields(strings.ToLower(s)) }

func unNo(f []string) []string {
	if len(f) > 0 && f[0] == "no" {
		return f[1:]
	}
	return f
}

func hasPrefix(f []string, w word) bool {
	return len(f) >= len(w) && slices.Equal(f[:len(w)], w)
}

// abbrevPrefix: f empieza por w, donde cada token de f puede ser una abreviatura de la palabra de w.
func abbrevPrefix(f []string, w word) bool {
	if len(f) < len(w) {
		return false
	}
	for i, x := range w {
		if !abbrev(f[i], x) {
			return false
		}
	}
	return true
}

var (
	maskRe = regexp.MustCompile(`(?i)<masked|<oculto>`)
	// secretWords: una línea con alguna de estas palabras (o una que acabe en -password o -key) lleva un secreto o un hash reversible. No se
	// muestra, no se audita y no se restaura: para eso está la rotación de credenciales.
	secretWords   = []string{"password", "secret", "key", "key-string", "authentication-key", "message-digest-key", "pre-shared-key", "community-string", "nopassword"}
	sectionStarts = []string{"interface ", "router ", "line ", "vlan ", "ip access-list ", "ipv6 access-list ", "mac access-list ", "route-map ", "class-map ",
		"policy-map ", "address-family ", "key chain ", "ip dhcp pool ", "vrf definition ", "crypto ", "archive", "track ", "ip sla "}
	nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,63}$`)
	wordRe = regexp.MustCompile(`^[A-Za-z0-9._:/+-]{1,64}$`)
)

func sectionLike(line string) bool {
	l := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(line), "no "))
	for _, p := range sectionStarts {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// hygiene son las reglas de toda línea, de cualquier familia: ASCII, '?', la lista negra del motor, enmascarados y todo lo que lleve un
// secreto o una autenticación.
func hygiene(line string) string {
	if err := asciiOnly(line); err != nil {
		return "caracteres fuera de ASCII imprimible (0x20-0x7e): IOS los recorta y una línea podría colar otro comando; hazlo a mano"
	}
	if strings.Contains(line, "?") {
		return "'?' abre la ayuda de IOS sin Enter"
	}
	if isDenied(line) {
		return "comando prohibido en modo asistido"
	}
	if maskRe.MatchString(line) {
		return "tiene secretos enmascarados"
	}
	if i, why := secretAt(tokens(line)); i >= 0 {
		return why
	}
	return ""
}

// secretAt da la posición de la primera palabra que marca un secreto o una autenticación (y por qué), o -1.
func secretAt(f []string) (int, string) {
	for i, w := range f {
		if slices.Contains(secretWords, w) || strings.HasSuffix(w, "-password") || strings.HasSuffix(w, "-key") {
			return i, "lleva un secreto o un hash reversible: no se muestra ni se audita; hazlo a mano o con la rotación"
		}
		if len(w) >= 5 && strings.HasPrefix("authentication", w) {
			return i, "authentication: lleva llaves o cambia cómo entra el tráfico; hazlo a mano"
		}
	}
	return -1, ""
}

// redact es lo único de una línea rechazada que sale del núcleo: si lleva un secreto, solo los tokens anteriores a la palabra del secreto y
// <oculto>. No depende del enmascarado (que puede ocultar la palabra equivocada). snmp-server community|host|user|group lleva el secreto
// justo después del subcomando.
func redact(line string) string {
	f, l := strings.Fields(line), tokens(line)
	cut := -1
	if i, _ := secretAt(l); i >= 0 {
		cut = i
	}
	for _, w := range []word{{"snmp-server", "community"}, {"snmp-server", "host"}, {"snmp-server", "user"}, {"snmp-server", "group"}} {
		if b := unNo(l); abbrevPrefix(b, w) {
			if n := len(l) - len(b) + len(w); cut < 0 || n < cut {
				cut = n
			}
		}
	}
	if cut < 0 {
		return Scrub(line, nil, true)
	}
	return strings.TrimSpace(strings.Join(f[:cut], " ") + " <oculto>")
}

// forbidden da el motivo de las familias que más se parecen a un cambio permitido; se comparan con abreviaturas. Es solo para explicar:
// lo que no está en la lista cerrada se rechaza igual.
var forbidden = []struct {
	w   word
	why string
}{
	{word{"ip", "route"}, "ruta estática: puede cortar el acceso o el tráfico; hazla a mano"},
	{word{"ipv6", "route"}, "ruta estática IPv6: puede cortar el acceso o el tráfico; hazla a mano"},
	{word{"ip", "default-gateway"}, "ruta por omisión (ip default-gateway): puede cortar el acceso"},
	{word{"ip", "routing"}, "ip routing: cambia el modo del equipo"},
	{word{"router"}, "router *: protocolo de enrutamiento; hazlo a mano"},
	{word{"access-list"}, "ACL numerada (access-list): hazla a mano"},
	{word{"ip", "access-list"}, "ACL: hazla a mano"},
	{word{"ipv6", "access-list"}, "ACL IPv6: hazla a mano"},
	{word{"mac", "access-list"}, "ACL MAC: hazla a mano"},
	{word{"ip", "access-group"}, "ACL aplicada a una interfaz: hazla a mano"},
	{word{"ipv6", "traffic-filter"}, "ACL IPv6 aplicada a una interfaz: hazla a mano"},
	{word{"route-map"}, "route-map: hazlo a mano"},
	{word{"ip", "prefix-list"}, "prefix-list: hazla a mano"},
	{word{"ip", "vrf"}, "vrf: hazlo a mano"},
	{word{"vrf"}, "vrf: hazlo a mano"},
	{word{"line"}, "line (consola, auxiliar y vty): un error corta el acceso"},
	{word{"aaa"}, "aaa: un error corta el acceso al equipo"},
	{word{"username"}, "usuarios locales: para eso está la rotación de credenciales"},
	{word{"enable"}, "enable secret/password: para eso está la rotación de credenciales"},
	{word{"crypto"}, "llaves y certificados (crypto): no se pueden inversar con certeza"},
	{word{"standby"}, "standby (HSRP): hazlo a mano"},
	{word{"vrrp"}, "vrrp: hazlo a mano"},
	{word{"glbp"}, "glbp: hazlo a mano"},
	{word{"ip", "ssh"}, "ip ssh: un error corta el acceso"},
	{word{"snmp-server", "community"}, "lleva un secreto (la comunidad): no se muestra ni se audita"},
	{word{"snmp-server", "user"}, "lleva un secreto: no se muestra ni se audita"},
	{word{"snmp-server", "host"}, "lleva un secreto (la comunidad): no se muestra ni se audita"},
	{word{"banner"}, "banner: texto con delimitadores, no se inversa con certeza"},
	{word{"macro"}, "macro: texto con delimitadores, no se inversa con certeza"},
	{word{"menu"}, "menu: texto con delimitadores, no se inversa con certeza"},
	{word{"vtp"}, "vtp: se propaga a otros equipos"},
	{word{"boot"}, "boot: cambia el arranque del equipo"},
	{word{"config-register"}, "config-register: cambia el arranque del equipo"},
	{word{"license"}, "licencias"},
	{word{"kron"}, "kron: ejecuta comandos programados"},
	{word{"archive"}, "archive: lo usa configure replace"},
	{word{"event"}, "eem: ejecuta comandos"},
	{word{"spanning-tree", "mode"}, "spanning-tree mode: reconverge todo el árbol, el uplink de gestión incluido; hazlo a mano"},
	{word{"spanning-tree", "extend"}, "spanning-tree extend system-id: cambia el identificador del puente y reconverge todo el árbol; hazlo a mano"},
	{word{"channel-group"}, "channel-group: parte de un Port-channel"},
	{word{"switchport", "trunk"}, "trunk: puede cortar el acceso"},
	{word{"switchport", "mode"}, "switchport mode: el modo del puerto no se cambia"},
	{word{"no", "switchport"}, "no switchport: pasa el puerto a capa 3"},
	{word{"interface"}, "interfaz completa: crearla o borrarla no se inversa con certeza"},
}

func forbiddenWhy(f []string) string {
	for _, x := range forbidden {
		g := f
		if x.w[0] != "no" {
			g = unNo(f)
		}
		if abbrevPrefix(g, x.w) {
			return x.why
		}
	}
	return ""
}

// ---- familias permitidas ----

// rctx es lo que la lista cerrada necesita saber del equipo: la gestión (no se toca), las VLAN activas y las interfaces que existen.
type rctx struct {
	mgIfaces map[string]bool // gi1/0/1, vlan99
	mgVlans  map[string]bool // "99"
	live     map[string]bool // VLAN activas en show vlan brief
	ifs      map[string]bool // interfaces del running
	max      int
}

// fam es una familia de líneas de la lista cerrada. Cada familia dice qué hace IOS con ella:
//   - one: un solo valor; la línea nueva sustituye a la anterior y `no X ...` quita el comando entero. Cambiar el valor manda solo la línea
//     nueva: un `no <viejo>` después borraría también el nuevo.
//   - keepNo (solo con one): IOS conserva la forma `no X` en el running en lugar de quitar la línea, así que quitar el valor sin sustituto
//     no se puede expresar y se rechaza.
//   - keyN > 0: una línea por clave, formada por el comando y sus primeros keyN argumentos (la dirección de `ntp server`): IOS guarda una sola
//     línea por clave, así que la línea nueva con la misma clave (`ntp server X prefer` sobre `ntp server X`) la reemplaza sin `no`, y un `no`
//     posterior borraría la nueva. Con otra clave, agregar antes de quitar.
//   - ninguna: una línea por valor (o sin valor); `no X valor` quita solo esa línea y el orden es agregar antes de quitar.
type fam struct {
	w      word
	no     bool // admite `no`
	chk    func(rc *rctx, neg bool, args []string) string
	one    bool
	keepNo bool
	keyN   int
}

func nargs(min, max int, ok func(string) bool) func(*rctx, bool, []string) string {
	return func(_ *rctx, neg bool, a []string) string {
		lo := min
		if neg {
			lo = 0
		}
		for _, x := range a {
			if x == "vrf" {
				return "nombra una VRF: hazlo a mano"
			}
		}
		if len(a) < lo || len(a) > max {
			return "forma que la lista cerrada no restaura (argumentos de más o de menos); hazlo a mano"
		}
		for _, x := range a {
			if x == "vrf" {
				return "nombra una VRF: hazlo a mano"
			}
			if ok != nil && !ok(x) {
				return fmt.Sprintf("argumento %q no válido para la lista cerrada", x)
			}
		}
		return ""
	}
}

func isIP(s string) bool   { _, err := netip.ParseAddr(s); return err == nil }
func isWord(s string) bool { return wordRe.MatchString(s) }
func isName(s string) bool { return nameRe.MatchString(s) }

func freeText(_ *rctx, neg bool, a []string) string {
	if len(a) == 0 && !neg {
		return "sin texto"
	}
	if len(strings.Join(a, " ")) > 200 {
		return "texto de más de 200 caracteres"
	}
	return ""
}

func ntpServer(rc *rctx, neg bool, a []string) string {
	if len(a) == 0 && neg {
		return ""
	}
	if len(a) < 1 || len(a) > 2 || !isIP(a[0]) || len(a) == 2 && a[1] != "prefer" {
		return "ntp server solo con una dirección IP (y prefer); hazlo a mano"
	}
	return ""
}

func srcIf(rc *rctx, neg bool, a []string) string {
	if len(a) != 1 || !rc.ifs[strings.ToLower(iosxe.ShortIf(a[0]))] {
		return "nombra una interfaz que el equipo no tiene"
	}
	return ""
}

func errdisableInterval(_ *rctx, neg bool, a []string) string {
	if len(a) == 0 && neg || len(a) == 1 && isNum(a[0], 30, 86400) {
		return ""
	}
	return "errdisable recovery interval solo con un número de 30 a 86400"
}

// loggingBuffered: IOS deja `no logging buffered` (sin argumentos) y apaga el buffer; `no logging buffered N` no es una forma que se restaure.
func loggingBuffered(rc *rctx, neg bool, a []string) string {
	if neg && len(a) > 0 {
		return "`no logging buffered N`: IOS lo deja como `no logging buffered` y apaga el buffer; hazlo a mano"
	}
	return nargs(0, 2, isWord)(rc, neg, a)
}

func stormLevel(_ *rctx, neg bool, a []string) string {
	if len(a) == 0 && neg || len(a) >= 2 && len(a) <= 5 && a[0] == "level" {
		for _, x := range a {
			if !isWord(x) {
				return "argumento de storm-control no válido"
			}
		}
		return ""
	}
	return "storm-control solo broadcast|multicast|unicast level X o action shutdown|trap"
}

func oneOfArg(vals ...string) func(*rctx, bool, []string) string {
	return func(_ *rctx, neg bool, a []string) string {
		if len(a) != 1 || !slices.Contains(vals, a[0]) {
			return "valor fuera de la lista cerrada (" + strings.Join(vals, "|") + ")"
		}
		return ""
	}
}

func isNum(s string, lo, hi int) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= lo && n <= hi
}

// vlanArg revisa la VLAN que nombra una línea de interfaz: existe, está activa y no es la de gestión.
func (rc *rctx) vlanArg(neg bool, a []string, special ...string) string {
	switch {
	case len(a) == 0 && neg:
		return ""
	case len(a) != 1:
		return "falta la VLAN o sobran argumentos"
	case slices.Contains(special, a[0]):
		return ""
	case !isNum(a[0], 1, 4094):
		return "VLAN fuera de 1-4094"
	case rc.mgVlans[a[0]]:
		return "nombra la VLAN de gestión: no se toca"
	case !neg && !rc.live[a[0]]:
		return "nombra una VLAN que el equipo no tiene activa (IOS la crearía y, con VTP servidor, la propagaría): créala por separado"
	}
	return ""
}

var globalFams = []fam{
	{w: word{"hostname"}, chk: nargs(1, 1, isName), one: true},
	{w: word{"logging", "host"}, no: true, chk: nargs(1, 1, isIP), keyN: 1},
	{w: word{"logging", "buffered"}, no: true, chk: loggingBuffered, one: true, keepNo: true},
	{w: word{"logging", "trap"}, no: true, chk: nargs(0, 1, isWord), one: true, keepNo: true},
	{w: word{"logging", "facility"}, no: true, chk: nargs(1, 1, isWord), one: true},
	{w: word{"logging", "source-interface"}, no: true, chk: srcIf, one: true},
	{w: word{"ntp", "server"}, no: true, chk: ntpServer, keyN: 1},
	{w: word{"snmp-server", "location"}, no: true, chk: freeText, one: true},
	{w: word{"snmp-server", "contact"}, no: true, chk: freeText, one: true},
	{w: word{"ip", "domain-name"}, no: true, chk: nargs(1, 1, isName), one: true},
	{w: word{"ip", "domain", "name"}, no: true, chk: nargs(1, 1, isName), one: true},
	// IOS junta los servidores en una sola línea (`ip name-server A B`): solo se admite uno por línea; con varios, quitar uno no es quitar la línea.
	{w: word{"ip", "name-server"}, no: true, chk: nargs(1, 1, isIP), keyN: 1},
	{w: word{"clock", "timezone"}, no: true, chk: nargs(2, 3, isWord), one: true},
	{w: word{"clock", "summer-time"}, no: true, chk: nargs(1, 12, isWord), one: true},
	{w: word{"service", "timestamps", "debug"}, no: true, chk: nargs(0, 5, isWord), one: true, keepNo: true},
	{w: word{"service", "timestamps", "log"}, no: true, chk: nargs(0, 5, isWord), one: true, keepNo: true},
	{w: word{"spanning-tree", "portfast", "default"}, no: true, chk: nargs(0, 0, nil)},
	{w: word{"errdisable", "recovery", "cause"}, no: true, chk: nargs(1, 1, isWord)},
	{w: word{"errdisable", "recovery", "interval"}, no: true, chk: errdisableInterval, one: true},
}

var ifaceFams = []fam{
	{w: word{"description"}, no: true, chk: freeText, one: true},
	{w: word{"switchport", "access", "vlan"}, no: true, chk: func(rc *rctx, neg bool, a []string) string { return rc.vlanArg(neg, a) }, one: true},
	{w: word{"switchport", "voice", "vlan"}, no: true, chk: func(rc *rctx, neg bool, a []string) string { return rc.vlanArg(neg, a, "dot1p", "untagged", "none") }, one: true},
	{w: word{"shutdown"}, no: true, chk: nargs(0, 0, nil)},
	{w: word{"spanning-tree", "portfast"}, no: true, chk: nargs(0, 1, func(s string) bool { return s == "disable" }), one: true},
	{w: word{"spanning-tree", "bpduguard"}, no: true, chk: nargs(0, 1, func(s string) bool { return s == "enable" || s == "disable" }), one: true},
	{w: word{"storm-control", "broadcast"}, no: true, chk: stormLevel, one: true},
	{w: word{"storm-control", "multicast"}, no: true, chk: stormLevel, one: true},
	{w: word{"storm-control", "unicast"}, no: true, chk: stormLevel, one: true},
	// shutdown y trap pueden estar juntas: una línea por acción.
	{w: word{"storm-control", "action"}, no: true, chk: oneOfArg("shutdown", "trap")},
}

// vlanFams: dentro de `vlan N` solo el nombre; `no name` lo regresa al nombre por omisión (VLANxxxx).
var vlanFams = []fam{{w: word{"name"}, no: true, chk: func(_ *rctx, _ bool, a []string) string {
	if len(a) != 1 || !isName(a[0]) || len(a[0]) > 32 {
		return "de una VLAN solo se restaura el nombre (name)"
	}
	return ""
}, one: true}}

// engineAllowed son los prefijos que el motor exige además (el filtro fino es CheckDevice).
func engineAllowed() []string {
	out := []string{"interface", "vlan", "name"}
	for _, fs := range [][]fam{globalFams, ifaceFams} {
		for _, f := range fs {
			out = append(out, strings.Join(f.w, " "))
		}
	}
	return out
}

func (rc *rctx) matchFam(fams []fam, line string) string {
	f := tokens(line)
	body := unNo(f)
	neg := len(body) != len(f)
	for _, fm := range fams {
		if hasPrefix(body, fm.w) {
			if neg && !fm.no {
				return "no se restaura con `no`: hazlo a mano"
			}
			return fm.chk(rc, neg, body[len(fm.w):])
		}
	}
	if why := forbiddenWhy(f); why != "" {
		return why
	}
	for _, fm := range fams {
		if abbrevPrefix(body, fm.w) {
			return fmt.Sprintf("abreviatura de %q: IOS la expande, pero el plan exige la palabra completa", strings.Join(fm.w, " "))
		}
	}
	return "fuera de la lista cerrada de restore-diff: hazlo a mano"
}

// access revisa que la interfaz sea un puerto físico de acceso (la misma que acepta ports) en cada estado dado, que no sea la de gestión
// y que no lleve su VLAN.
func (rc *rctx) access(hdr string, sides []cfgState) string {
	name := strings.TrimSpace(strings.TrimPrefix(hdr, "interface "))
	switch {
	case rc.mgIfaces[strings.ToLower(iosxe.ShortIf(name))]:
		return "interfaz de gestión: por ella estás conectado, no se toca"
	case !ValidInterface(name):
		return "no es un puerto físico (SVI, Port-channel, loopback, subinterfaz...): hazlo a mano"
	}
	for _, st := range sides {
		access, vlan := false, "1" // sin `switchport access vlan` el puerto está en la VLAN 1
		for _, l := range st.lists[pathKey([]string{hdr})] {
			f := tokens(l)
			switch {
			case l == "switchport mode access":
				access = true
			case hasPrefix(f, word{"switchport", "mode"}), hasPrefix(f, word{"switchport", "trunk"}), hasPrefix(f, word{"channel-group"}),
				hasPrefix(f, word{"ip", "address"}), hasPrefix(f, word{"ipv6", "address"}), hasPrefix(f, word{"vrf", "forwarding"}),
				hasPrefix(f, word{"ip", "vrf", "forwarding"}), l == "no switchport":
				return "no es un puerto físico de acceso (switchport mode access, sin trunk, canal, capa 3 ni VRF) en el equipo y en el respaldo: hazlo a mano"
			case hasPrefix(f, word{"switchport", "access", "vlan"}):
				vlan = f[len(f)-1]
			case hasPrefix(f, word{"switchport", "voice", "vlan"}):
				if rc.mgVlans[f[len(f)-1]] {
					return "lleva la VLAN de gestión (" + f[len(f)-1] + "): cambiarla podría cortar la sesión"
				}
			}
		}
		if rc.mgVlans[vlan] {
			return "lleva la VLAN de gestión (" + vlan + "): cambiarla podría cortar la sesión"
		}
		if !access {
			return "no es un puerto físico de acceso (switchport mode access, sin trunk, canal, capa 3 ni VRF) en el equipo y en el respaldo: hazlo a mano"
		}
	}
	return ""
}

// refuse dice por qué una línea (en su sección) no se restaura; vacío si se puede. sides son los estados en que la interfaz debe ser de acceso.
func (rc *rctx) refuse(path []string, line string, sides []cfgState) string {
	if why := hygiene(line); why != "" {
		return why
	}
	if len(path) > 0 {
		if why := hygiene(path[0]); why != "" {
			return why
		}
	}
	switch {
	case len(path) == 0:
		return rc.matchFam(globalFams, line)
	case len(path) == 1 && strings.HasPrefix(path[0], "interface "):
		if why := rc.access(path[0], sides); why != "" {
			return why
		}
		return rc.matchFam(ifaceFams, line)
	case len(path) == 1 && strings.HasPrefix(path[0], "vlan "):
		f := tokens(path[0])
		switch g := unNo(tokens(line)); {
		case len(f) != 2 || !isNum(f[1], 1, 4094):
			return "VLAN no válida"
		case rc.mgVlans[f[1]]:
			return "VLAN de la interfaz de gestión: no se toca"
		case len(g) == 0 || g[0] != "name":
			return "de una VLAN solo se restaura el nombre (name)"
		}
		return rc.matchFam(vlanFams, line)
	}
	why := forbiddenWhy(tokens(path[0]))
	if why == "" {
		why = "sección fuera de la lista cerrada de restore-diff"
	}
	return why + " (" + path[0] + "): hazlo a mano"
}

// ---- gestión ----

// parseAddrPort lee "10.0.0.2.22" (IOS), "10.0.0.2:22" o "2001:db8::1.22".
func parseAddrPort(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	if i := strings.LastIndex(s, "."); i > 0 {
		if _, err := strconv.Atoi(s[i+1:]); err == nil {
			if a, err := netip.ParseAddr(s[:i]); err == nil {
				return a.Unmap(), true
			}
		}
	}
	return netip.Addr{}, false
}

// sessionLocals da, de `show users` (la línea marcada con * es la sesión actual y termina en la dirección de origen) y de
// `show tcp brief` (conexiones ESTAB), las direcciones locales del equipo por las que entra esa dirección de origen. IOS 15.2 e IOS-XE
// imprimen las dos tablas igual (sin validar en laboratorio).
func sessionLocals(users, tcp string) []netip.Addr {
	core, ok := sessionOrigin(users)
	if !ok {
		return nil
	}
	var out []netip.Addr
	for _, l := range strings.Split(tcp, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || !strings.EqualFold(f[len(f)-1], "ESTAB") {
			continue
		}
		loc, ok1 := parseAddrPort(f[len(f)-3])
		far, ok2 := parseAddrPort(f[len(f)-2])
		if ok1 && ok2 && far == core && !slices.Contains(out, loc) {
			out = append(out, loc)
		}
	}
	return out
}

// sessionOrigin es la dirección de origen de la sesión actual: la línea marcada con * de `show users` termina en ella.
func sessionOrigin(users string) (netip.Addr, bool) {
	var core netip.Addr
	for _, l := range strings.Split(users, "\n") {
		if t := strings.TrimSpace(l); strings.HasPrefix(t, "*") {
			if f := strings.Fields(t); len(f) > 1 {
				if a, err := netip.ParseAddr(f[len(f)-1]); err == nil {
					core = a.Unmap()
				}
			}
		}
	}
	return core, core.IsValid()
}

// egressCmds son las lecturas del camino de regreso hacia el origen: la tabla de su familia (IPv4 o IPv6) y, si la interfaz que lleva la
// sesión está en una VRF, la de esa VRF (la global no dice nada de ella).
func egressCmds(origin netip.Addr, vrf string) []string {
	af, v := "ip", ""
	if origin.Is6() {
		af = "ipv6"
	}
	if vrf != "" {
		v = "vrf " + vrf + " "
	}
	return []string{"show " + af + " cef " + v + origin.String(), "show " + af + " route " + v + origin.String()}
}

// ifaceNodes indexa las interfaces del running por su nombre corto en minúsculas.
func ifaceNodes(root *iosconf.Node) map[string]*iosconf.Node {
	have := map[string]*iosconf.Node{}
	for _, n := range root.Children {
		if k, ok := ifaceKey(n.Line); ok {
			have[k] = n
		}
	}
	return have
}

// carrying son las interfaces que llevan la dirección local de la sesión.
func carrying(have map[string]*iosconf.Node, local netip.Addr) []string {
	var out []string
	for k, n := range have {
		for _, c := range n.Children {
			f := strings.Fields(c.Line)
			if len(f) >= 3 && (f[0] == "ip" || f[0] == "ipv6") && f[1] == "address" {
				if b, err := netip.ParseAddr(strings.SplitN(f[2], "/", 2)[0]); err == nil && b.Unmap() == local {
					out = append(out, k)
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// vrfOf es la VRF de una interfaz (`vrf forwarding X` o `ip vrf forwarding X`); vacío si está en la global.
func vrfOf(n *iosconf.Node) string {
	for _, c := range n.Children {
		if f := strings.Fields(c.Line); len(f) == 3 && f[0] == "vrf" && f[1] == "forwarding" {
			return f[2]
		} else if len(f) == 4 && f[0] == "ip" && f[1] == "vrf" && f[2] == "forwarding" {
			return f[3]
		}
	}
	return ""
}

// egressReads son las lecturas del camino de regreso: nil si no se conoce el origen o la VRF de la interfaz de la sesión no se puede nombrar en
// un comando (entonces no hay respuesta y se pide --mgmt-if). La VRF es la de la única interfaz que lleva la IP local; si no es única, se pide
// la global y --mgmt-if es obligatorio de todos modos. vrf dice si la consulta es de una VRF.
func egressReads(root *iosconf.Node, outs map[string]string) (cmds []string, vrf string) {
	origin, ok := sessionOrigin(outs["show users"])
	if !ok {
		return nil, ""
	}
	if locals := sessionLocals(outs["show users"], outs["show tcp brief"]); len(locals) == 1 {
		have := ifaceNodes(root)
		if c := carrying(have, locals[0]); len(c) == 1 {
			vrf = vrfOf(have[c[0]])
		}
	}
	if vrf != "" && !nameRe.MatchString(vrf) {
		return nil, vrf
	}
	return egressCmds(origin, vrf), vrf
}

// hasGlobal dice si el running tiene esa línea global.
func hasGlobal(root *iosconf.Node, line string) bool {
	for _, n := range root.Children {
		if n.Line == line {
			return true
		}
	}
	return false
}

func ifaceKey(header string) (string, bool) {
	name, ok := strings.CutPrefix(strings.TrimSpace(header), "interface ")
	if !ok {
		return "", false
	}
	return strings.ToLower(iosxe.ShortIf(strings.TrimSpace(name))), true
}

// onLink dice si alguna dirección de la interfaz (`ip address A M [secondary]` o `ipv6 address P/L`) tiene al origen en su subred.
func onLink(n *iosconf.Node, origin netip.Addr) bool {
	for _, c := range n.Children {
		f := strings.Fields(c.Line)
		if len(f) < 3 || f[1] != "address" {
			continue
		}
		var p netip.Prefix
		var err error
		switch {
		case f[0] == "ip" && len(f) >= 4:
			a, e1 := netip.ParseAddr(f[2])
			m, e2 := netip.ParseAddr(f[3])
			if e1 != nil || e2 != nil || !a.Is4() || !m.Is4() {
				continue
			}
			b := m.As4()
			p = netip.PrefixFrom(a, bits.OnesCount32(binary.BigEndian.Uint32(b[:])))
		case f[0] == "ipv6":
			p, err = netip.ParsePrefix(f[2])
			if err != nil {
				continue
			}
		default:
			continue
		}
		if p.Masked().Contains(origin) {
			return true
		}
	}
	return false
}

// managementOf encuentra por dónde está conectado el núcleo. La gestión no es solo la interfaz que lleva la IP local de la sesión (show users +
// show tcp brief): en un switch con `ip routing` la sesión puede entrar a una Loopback o a otra SVI y el tráfico de regreso salir por otra
// interfaz. Se protegen las dos: la que lleva la IP local y la de salida hacia el origen (show ip cef, o show ip route), con la VLAN de cada
// una (una SVI: su VLAN; un puerto físico: su VLAN de acceso, la 1 implícita y la de voz) en todos los puertos de acceso. Con `ip routing`
// y sin certeza de la salida, o si la IP local no es única, no se restaura salvo que se indique la interfaz a mano (explicit).
func managementOf(root *iosconf.Node, outs map[string]string, explicit string) (ifaces, vlans map[string]bool, err error) {
	ifaces, vlans = map[string]bool{}, map[string]bool{}
	have := ifaceNodes(root)
	fail := func(code string, kv ...any) (map[string]bool, map[string]bool, error) {
		return nil, nil, newRefusal(ErrRestoreRefused, "assist.restore_refused", i18n.Tx(code, kv...))
	}
	e := strings.TrimSpace(explicit)
	if e != "" {
		k := strings.ToLower(iosxe.ShortIf(e))
		if have[k] == nil {
			return fail("assist.restore_refused.la_interfaz_de_gestion_indicada", "interface", e)
		}
		ifaces[k] = true
	}
	switch locals := sessionLocals(outs["show users"], outs["show tcp brief"]); {
	case len(locals) == 1:
		carry := carrying(have, locals[0])
		if len(carry) == 1 {
			ifaces[carry[0]] = true
		} else if e == "" {
			return fail("assist.restore_refused.no_se_pudo_identificar_la", "ip", locals[0], "count", len(carry))
		}
	case e == "":
		return fail("assist.restore_refused.no_se_pudo_identificar_la2", "count", len(locals))
	}
	// ¿Enruta? Un router trae `ip routing` activo y no lo imprime, así que se decide por la salida misma: una tabla de rutas = enruta; `Default
	// gateway is X` o `IP routing not enabled` = un switch L2, y la gestión es la IP local; `no ip routing` también es sin enrutamiento. Si no se
	// sabe (o una línea `ip routing` contradice a la respuesta) no se adivina.
	// `no ip routing` solo apaga IPv4: con un origen IPv6 la salida se lee igual. Una respuesta de «sin enrutamiento» solo vale para IPv4 en la
	// tabla global: en una VRF o en IPv6 un switch L2 no tiene qué decir, y sin certeza se pide --mgmt-if.
	origin, hasOrigin := sessionOrigin(outs["show users"])
	if !hasGlobal(root, "no ip routing") || origin.Is6() {
		var out []string
		ok, off := false, false
		cmds, vrf := egressReads(root, outs)
		for _, c := range cmds {
			if out, ok = iosxe.ParseEgress(outs[c]); ok {
				break
			}
			off = off || iosxe.RoutingOff(outs[c])
		}
		switch {
		case ok:
			for _, n := range out {
				ifaces[strings.ToLower(n)] = true
			}
		case off && vrf == "" && !origin.Is6() && !hasGlobal(root, "ip routing"):
		case e == "":
			return fail("assist.restore_refused.no_se_pudo_saber_si")
		}
	}
	// Toda interfaz cuya subred contiene al origen responde por él (un switch L2 con varias SVI, un router con dos redes en el segmento): se
	// protege junto con su VLAN, sea cual sea la IP local o la salida que dijo la tabla.
	if hasOrigin {
		for k, n := range have {
			if onLink(n, origin) {
				ifaces[k] = true
			}
		}
	}
	for k := range ifaces {
		if v, ok := strings.CutPrefix(k, "vlan"); ok {
			vlans[v] = true
		}
		n := have[k]
		if n == nil {
			continue // una salida que el running no configura (un Port-channel dinámico, por ejemplo): se protege el nombre
		}
		access, l3, trunk := "", false, false
		for _, c := range n.Children {
			f := strings.Fields(c.Line)
			switch {
			case len(f) == 4 && f[0] == "switchport" && f[1] == "access" && f[2] == "vlan":
				access = f[3]
				vlans[f[3]] = true
			case len(f) == 4 && f[0] == "switchport" && f[1] == "voice" && f[2] == "vlan":
				vlans[f[3]] = true
			case c.Line == "no switchport" || len(f) >= 3 && f[0] == "ip" && f[1] == "address":
				l3 = true
			case len(f) == 3 && f[0] == "switchport" && f[1] == "mode" && f[2] == "trunk":
				trunk = true
			}
		}
		if access == "" && !l3 && !trunk && ValidInterface(strings.TrimSpace(strings.TrimPrefix(n.Line, "interface "))) {
			vlans["1"] = true // sin `switchport access vlan` un puerto físico está en la VLAN 1
		}
	}
	return ifaces, vlans, nil
}
