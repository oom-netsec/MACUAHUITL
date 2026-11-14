package assist

import (
	"encoding/binary"
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
func hygiene(line string) i18n.Text {
	if err := asciiOnly(line); err != nil {
		return lt("caracteres fuera de ASCII imprimible (0x20-0x7e): IOS los recorta y una línea podría colar otro comando; hazlo a mano", "characters outside printable ASCII (0x20-0x7e): IOS trims them and a line could smuggle in another command; do it by hand")
	}
	if strings.Contains(line, "?") {
		return lt("'?' abre la ayuda de IOS sin Enter", "'?' opens the IOS help without Enter")
	}
	if isDenied(line) {
		return lt("comando prohibido en modo asistido", "command forbidden in assisted mode")
	}
	if maskRe.MatchString(line) {
		return lt("tiene secretos enmascarados", "has masked secrets")
	}
	if i, why := secretAt(tokens(line)); i >= 0 {
		return why
	}
	return i18n.Text{}
}

// secretAt da la posición de la primera palabra que marca un secreto o una autenticación (y por qué), o -1.
func secretAt(f []string) (int, i18n.Text) {
	for i, w := range f {
		if slices.Contains(secretWords, w) || strings.HasSuffix(w, "-password") || strings.HasSuffix(w, "-key") {
			return i, lt("lleva un secreto o un hash reversible: no se muestra ni se audita; hazlo a mano o con la rotación", "carries a secret or a reversible hash: it is neither shown nor audited; do it by hand or with the rotation")
		}
		if len(w) >= 5 && strings.HasPrefix("authentication", w) {
			return i, lt("authentication: lleva llaves o cambia cómo entra el tráfico; hazlo a mano", "authentication: carries keys or changes how traffic is admitted; do it by hand")
		}
	}
	return -1, i18n.Text{}
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
	why i18n.Text
}{
	{word{"ip", "route"}, lt("ruta estática: puede cortar el acceso o el tráfico; hazla a mano", "static route: it can cut access or traffic; do it by hand")},
	{word{"ipv6", "route"}, lt("ruta estática IPv6: puede cortar el acceso o el tráfico; hazla a mano", "IPv6 static route: it can cut access or traffic; do it by hand")},
	{word{"ip", "default-gateway"}, lt("ruta por omisión (ip default-gateway): puede cortar el acceso", "default route (ip default-gateway): it can cut access")},
	{word{"ip", "routing"}, lt("ip routing: cambia el modo del equipo", "ip routing: it changes the device mode")},
	{word{"router"}, lt("router *: protocolo de enrutamiento; hazlo a mano", "router *: routing protocol; do it by hand")},
	{word{"access-list"}, lt("ACL numerada (access-list): hazla a mano", "numbered ACL (access-list): do it by hand")},
	{word{"ip", "access-list"}, lt("ACL: hazla a mano", "ACL: do it by hand")},
	{word{"ipv6", "access-list"}, lt("ACL IPv6: hazla a mano", "IPv6 ACL: do it by hand")},
	{word{"mac", "access-list"}, lt("ACL MAC: hazla a mano", "MAC ACL: do it by hand")},
	{word{"ip", "access-group"}, lt("ACL aplicada a una interfaz: hazla a mano", "ACL applied to an interface: do it by hand")},
	{word{"ipv6", "traffic-filter"}, lt("ACL IPv6 aplicada a una interfaz: hazla a mano", "IPv6 ACL applied to an interface: do it by hand")},
	{word{"route-map"}, lt("route-map: hazlo a mano", "route-map: do it by hand")},
	{word{"ip", "prefix-list"}, lt("prefix-list: hazla a mano", "prefix-list: do it by hand")},
	{word{"ip", "vrf"}, lt("vrf: hazlo a mano", "vrf: do it by hand")},
	{word{"vrf"}, lt("vrf: hazlo a mano", "vrf: do it by hand")},
	{word{"line"}, lt("line (consola, auxiliar y vty): un error corta el acceso", "line (console, auxiliary and vty): a mistake cuts access")},
	{word{"aaa"}, lt("aaa: un error corta el acceso al equipo", "aaa: a mistake cuts access to the device")},
	{word{"username"}, lt("usuarios locales: para eso está la rotación de credenciales", "local users: that is what the credential rotation is for")},
	{word{"enable"}, lt("enable secret/password: para eso está la rotación de credenciales", "enable secret/password: that is what the credential rotation is for")},
	{word{"crypto"}, lt("llaves y certificados (crypto): no se pueden inversar con certeza", "keys and certificates (crypto): they cannot be reversed with certainty")},
	{word{"standby"}, lt("standby (HSRP): hazlo a mano", "standby (HSRP): do it by hand")},
	{word{"vrrp"}, lt("vrrp: hazlo a mano", "vrrp: do it by hand")},
	{word{"glbp"}, lt("glbp: hazlo a mano", "glbp: do it by hand")},
	{word{"ip", "ssh"}, lt("ip ssh: un error corta el acceso", "ip ssh: a mistake cuts access")},
	{word{"snmp-server", "community"}, lt("lleva un secreto (la comunidad): no se muestra ni se audita", "carries a secret (the community): it is neither shown nor audited")},
	{word{"snmp-server", "user"}, lt("lleva un secreto: no se muestra ni se audita", "carries a secret: it is neither shown nor audited")},
	{word{"snmp-server", "host"}, lt("lleva un secreto (la comunidad): no se muestra ni se audita", "carries a secret (the community): it is neither shown nor audited")},
	{word{"banner"}, lt("banner: texto con delimitadores, no se inversa con certeza", "banner: text with delimiters, it cannot be reversed with certainty")},
	{word{"macro"}, lt("macro: texto con delimitadores, no se inversa con certeza", "macro: text with delimiters, it cannot be reversed with certainty")},
	{word{"menu"}, lt("menu: texto con delimitadores, no se inversa con certeza", "menu: text with delimiters, it cannot be reversed with certainty")},
	{word{"vtp"}, lt("vtp: se propaga a otros equipos", "vtp: it propagates to other devices")},
	{word{"boot"}, lt("boot: cambia el arranque del equipo", "boot: it changes the device startup")},
	{word{"config-register"}, lt("config-register: cambia el arranque del equipo", "config-register: it changes the device startup")},
	{word{"license"}, lt("licencias", "licenses")},
	{word{"kron"}, lt("kron: ejecuta comandos programados", "kron: it runs scheduled commands")},
	{word{"archive"}, lt("archive: lo usa configure replace", "archive: used by configure replace")},
	{word{"event"}, lt("eem: ejecuta comandos", "eem: it runs commands")},
	{word{"spanning-tree", "mode"}, lt("spanning-tree mode: reconverge todo el árbol, el uplink de gestión incluido; hazlo a mano", "spanning-tree mode: it reconverges the whole tree, the management uplink included; do it by hand")},
	{word{"spanning-tree", "extend"}, lt("spanning-tree extend system-id: cambia el identificador del puente y reconverge todo el árbol; hazlo a mano", "spanning-tree extend system-id: it changes the bridge identifier and reconverges the whole tree; do it by hand")},
	{word{"channel-group"}, lt("channel-group: parte de un Port-channel", "channel-group: part of a Port-channel")},
	{word{"switchport", "trunk"}, lt("trunk: puede cortar el acceso", "trunk: it can cut access")},
	{word{"switchport", "mode"}, lt("switchport mode: el modo del puerto no se cambia", "switchport mode: the port mode is not changed")},
	{word{"no", "switchport"}, lt("no switchport: pasa el puerto a capa 3", "no switchport: it turns the port into layer 3")},
	{word{"interface"}, lt("interfaz completa: crearla o borrarla no se inversa con certeza", "whole interface: creating or deleting it cannot be reversed with certainty")},
}

func forbiddenWhy(f []string) i18n.Text {
	for _, x := range forbidden {
		g := f
		if x.w[0] != "no" {
			g = unNo(f)
		}
		if abbrevPrefix(g, x.w) {
			return x.why
		}
	}
	return i18n.Text{}
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
	chk    func(rc *rctx, neg bool, args []string) i18n.Text
	one    bool
	keepNo bool
	keyN   int
}

func nargs(min, max int, ok func(string) bool) func(*rctx, bool, []string) i18n.Text {
	return func(_ *rctx, neg bool, a []string) i18n.Text {
		lo := min
		if neg {
			lo = 0
		}
		for _, x := range a {
			if x == "vrf" {
				return lt("nombra una VRF: hazlo a mano", "names a VRF: do it by hand")
			}
		}
		if len(a) < lo || len(a) > max {
			return lt("forma que la lista cerrada no restaura (argumentos de más o de menos); hazlo a mano", "form that the closed list does not restore (too many or too few arguments); do it by hand")
		}
		for _, x := range a {
			if x == "vrf" {
				return lt("nombra una VRF: hazlo a mano", "names a VRF: do it by hand")
			}
			if ok != nil && !ok(x) {
				return lt("argumento %q no válido para la lista cerrada", "argument %q is not valid for the closed list", x)
			}
		}
		return i18n.Text{}
	}
}

func isIP(s string) bool   { _, err := netip.ParseAddr(s); return err == nil }
func isWord(s string) bool { return wordRe.MatchString(s) }
func isName(s string) bool { return nameRe.MatchString(s) }

func freeText(_ *rctx, neg bool, a []string) i18n.Text {
	if len(a) == 0 && !neg {
		return lt("sin texto", "no text")
	}
	if len(strings.Join(a, " ")) > 200 {
		return lt("texto de más de 200 caracteres", "text longer than 200 characters")
	}
	return i18n.Text{}
}

func ntpServer(rc *rctx, neg bool, a []string) i18n.Text {
	if len(a) == 0 && neg {
		return i18n.Text{}
	}
	if len(a) < 1 || len(a) > 2 || !isIP(a[0]) || len(a) == 2 && a[1] != "prefer" {
		return lt("ntp server solo con una dirección IP (y prefer); hazlo a mano", "ntp server only with an IP address (and prefer); do it by hand")
	}
	return i18n.Text{}
}

func srcIf(rc *rctx, neg bool, a []string) i18n.Text {
	if len(a) != 1 || !rc.ifs[strings.ToLower(iosxe.ShortIf(a[0]))] {
		return lt("nombra una interfaz que el equipo no tiene", "names an interface that the device does not have")
	}
	return i18n.Text{}
}

func errdisableInterval(_ *rctx, neg bool, a []string) i18n.Text {
	if len(a) == 0 && neg || len(a) == 1 && isNum(a[0], 30, 86400) {
		return i18n.Text{}
	}
	return lt("errdisable recovery interval solo con un número de 30 a 86400", "errdisable recovery interval only with a number from 30 to 86400")
}

// loggingBuffered: IOS deja `no logging buffered` (sin argumentos) y apaga el buffer; `no logging buffered N` no es una forma que se restaure.
func loggingBuffered(rc *rctx, neg bool, a []string) i18n.Text {
	if neg && len(a) > 0 {
		return lt("`no logging buffered N`: IOS lo deja como `no logging buffered` y apaga el buffer; hazlo a mano", "`no logging buffered N`: IOS leaves it as `no logging buffered` and turns the buffer off; do it by hand")
	}
	return nargs(0, 2, isWord)(rc, neg, a)
}

func stormLevel(_ *rctx, neg bool, a []string) i18n.Text {
	if len(a) == 0 && neg || len(a) >= 2 && len(a) <= 5 && a[0] == "level" {
		for _, x := range a {
			if !isWord(x) {
				return lt("argumento de storm-control no válido", "invalid storm-control argument")
			}
		}
		return i18n.Text{}
	}
	return lt("storm-control solo broadcast|multicast|unicast level X o action shutdown|trap", "storm-control only broadcast|multicast|unicast level X or action shutdown|trap")
}

func oneOfArg(vals ...string) func(*rctx, bool, []string) i18n.Text {
	return func(_ *rctx, neg bool, a []string) i18n.Text {
		if len(a) != 1 || !slices.Contains(vals, a[0]) {
			return lt("valor fuera de la lista cerrada (%s)", "value outside the closed list (%s)", strings.Join(vals, "|"))
		}
		return i18n.Text{}
	}
}

func isNum(s string, lo, hi int) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= lo && n <= hi
}

// vlanArg revisa la VLAN que nombra una línea de interfaz: existe, está activa y no es la de gestión.
func (rc *rctx) vlanArg(neg bool, a []string, special ...string) i18n.Text {
	switch {
	case len(a) == 0 && neg:
		return i18n.Text{}
	case len(a) != 1:
		return lt("falta la VLAN o sobran argumentos", "the VLAN is missing or there are too many arguments")
	case slices.Contains(special, a[0]):
		return i18n.Text{}
	case !isNum(a[0], 1, 4094):
		return lt("VLAN fuera de 1-4094", "VLAN outside 1-4094")
	case rc.mgVlans[a[0]]:
		return lt("nombra la VLAN de gestión: no se toca", "names the management VLAN: it is not touched")
	case !neg && !rc.live[a[0]]:
		return lt("nombra una VLAN que el equipo no tiene activa (IOS la crearía y, con VTP servidor, la propagaría): créala por separado", "names a VLAN that the device does not have active (IOS would create it and, with a VTP server, propagate it): create it separately")
	}
	return i18n.Text{}
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
	{w: word{"switchport", "access", "vlan"}, no: true, chk: func(rc *rctx, neg bool, a []string) i18n.Text { return rc.vlanArg(neg, a) }, one: true},
	{w: word{"switchport", "voice", "vlan"}, no: true, chk: func(rc *rctx, neg bool, a []string) i18n.Text { return rc.vlanArg(neg, a, "dot1p", "untagged", "none") }, one: true},
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
var vlanFams = []fam{{w: word{"name"}, no: true, chk: func(_ *rctx, _ bool, a []string) i18n.Text {
	if len(a) != 1 || !isName(a[0]) || len(a[0]) > 32 {
		return lt("de una VLAN solo se restaura el nombre (name)", "only the name (name) of a VLAN is restored")
	}
	return i18n.Text{}
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

func (rc *rctx) matchFam(fams []fam, line string) i18n.Text {
	f := tokens(line)
	body := unNo(f)
	neg := len(body) != len(f)
	for _, fm := range fams {
		if hasPrefix(body, fm.w) {
			if neg && !fm.no {
				return lt("no se restaura con `no`: hazlo a mano", "it is not restored with `no`: do it by hand")
			}
			return fm.chk(rc, neg, body[len(fm.w):])
		}
	}
	if why := forbiddenWhy(f); !why.Empty() {
		return why
	}
	for _, fm := range fams {
		if abbrevPrefix(body, fm.w) {
			return lt("abreviatura de %q: IOS la expande, pero el plan exige la palabra completa", "abbreviation of %q: IOS expands it, but the plan requires the full word", strings.Join(fm.w, " "))
		}
	}
	return lt("fuera de la lista cerrada de restore-diff: hazlo a mano", "outside the closed restore-diff list: do it by hand")
}

// access revisa que la interfaz sea un puerto físico de acceso (la misma que acepta ports) en cada estado dado, que no sea la de gestión
// y que no lleve su VLAN.
func (rc *rctx) access(hdr string, sides []cfgState) i18n.Text {
	name := strings.TrimSpace(strings.TrimPrefix(hdr, "interface "))
	switch {
	case rc.mgIfaces[strings.ToLower(iosxe.ShortIf(name))]:
		return lt("interfaz de gestión: por ella estás conectado, no se toca", "management interface: you are connected through it, it is not touched")
	case !ValidInterface(name):
		return lt("no es un puerto físico (SVI, Port-channel, loopback, subinterfaz...): hazlo a mano", "not a physical port (SVI, Port-channel, loopback, subinterface...): do it by hand")
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
				return lt("no es un puerto físico de acceso (switchport mode access, sin trunk, canal, capa 3 ni VRF) en el equipo y en el respaldo: hazlo a mano", "not a physical access port (switchport mode access, no trunk, channel, layer 3 or VRF) on the device and in the backup: do it by hand")
			case hasPrefix(f, word{"switchport", "access", "vlan"}):
				vlan = f[len(f)-1]
			case hasPrefix(f, word{"switchport", "voice", "vlan"}):
				if rc.mgVlans[f[len(f)-1]] {
					return lt("lleva la VLAN de gestión (%s): cambiarla podría cortar la sesión", "carries the management VLAN (%s): changing it could cut the session", f[len(f)-1])
				}
			}
		}
		if rc.mgVlans[vlan] {
			return lt("lleva la VLAN de gestión (%s): cambiarla podría cortar la sesión", "carries the management VLAN (%s): changing it could cut the session", vlan)
		}
		if !access {
			return lt("no es un puerto físico de acceso (switchport mode access, sin trunk, canal, capa 3 ni VRF) en el equipo y en el respaldo: hazlo a mano", "not a physical access port (switchport mode access, no trunk, channel, layer 3 or VRF) on the device and in the backup: do it by hand")
		}
	}
	return i18n.Text{}
}

// refuse dice por qué una línea (en su sección) no se restaura; vacío si se puede. sides son los estados en que la interfaz debe ser de acceso.
func (rc *rctx) refuse(path []string, line string, sides []cfgState) i18n.Text {
	if why := hygiene(line); !why.Empty() {
		return why
	}
	if len(path) > 0 {
		if why := hygiene(path[0]); !why.Empty() {
			return why
		}
	}
	switch {
	case len(path) == 0:
		return rc.matchFam(globalFams, line)
	case len(path) == 1 && strings.HasPrefix(path[0], "interface "):
		if why := rc.access(path[0], sides); !why.Empty() {
			return why
		}
		return rc.matchFam(ifaceFams, line)
	case len(path) == 1 && strings.HasPrefix(path[0], "vlan "):
		f := tokens(path[0])
		switch g := unNo(tokens(line)); {
		case len(f) != 2 || !isNum(f[1], 1, 4094):
			return lt("VLAN no válida", "invalid VLAN")
		case rc.mgVlans[f[1]]:
			return lt("VLAN de la interfaz de gestión: no se toca", "VLAN of the management interface: it is not touched")
		case len(g) == 0 || g[0] != "name":
			return lt("de una VLAN solo se restaura el nombre (name)", "only the name (name) of a VLAN is restored")
		}
		return rc.matchFam(vlanFams, line)
	}
	why := forbiddenWhy(tokens(path[0]))
	if why.Empty() {
		why = lt("sección fuera de la lista cerrada de restore-diff", "section outside the closed restore-diff list")
	}
	return i18n.Join("", why, lt(" (%s): hazlo a mano", " (%s): do it by hand", path[0]))
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
