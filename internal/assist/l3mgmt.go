package assist

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Lote L3 y gestión de la fase 28d: ruta estática, loopback, helper-address, NTP, syslog, SNMP (community y usuario v3), banner motd y
// ACL de las líneas vty. Casi todas son configuración global: su línea base es la sección del running-config que tocan (capturada en Pre) y
// el motor verifica contra ella que la reversa la deje idéntica (run.go). Lo que la reversa no restauraría exactamente se rechaza aquí,
// con el motivo. El patrón «agregar»: si la línea exacta ya está no hay nada que cambiar; si hay una variante que el `no` no restauraría, se rechaza.

// SessionSourceKey es la clave con que el servicio entrega, junto a las salidas de Pre, la IP local de la sesión con el equipo (la que el
// equipo ve como origen, salvo NAT en medio). Vacía o ausente = no se pudo saber, y vty-acl rechaza en vez de inventarla.
const SessionSourceKey = "@sesion-origen"

const (
	routeCmd     = "show running-config | include ^ip route"
	ntpCmd       = "show running-config | include ^ntp"
	loggingCmd   = "show running-config | include ^(no )*logging" // incluye `no logging trap`, que algunas versiones dejan en el running
	showUsersCmd = "show users"
	snmpCommCmd  = "show running-config | include ^snmp-server community"
	snmpGroupCmd = "show running-config | include ^snmp-server group"
	vtyCmd       = "show running-config | section ^line vty"
	bannerCmd    = "show running-config | section banner motd"
)

// origin es una IP de origen de la sesión con la que se explica un rechazo.
// what es "1" para la IP que ve el equipo y "2" para la local de la app: el catálogo escribe la frase en cada idioma ({what|uno|dos}).
type origin struct {
	addr netip.Addr
	what string
}

// sessionOrigins da las IP de origen que importan: la que el equipo ve (de show users, como restaurar; obligatoria) y la local de la app si
// difiere (con NAT o VPN no es la misma). Si no se puede saber la que ve el equipo se rechaza en vez de suponerla.
func sessionOrigins(device string, outs map[string]string) ([]origin, error) {
	seen, ok := sessionOrigin(outs[showUsersCmd])
	if !ok || seen.IsUnspecified() {
		return nil, refuseSnippet("assist.refused.no_se_pudo_obtener_la", "device", device)
	}
	out := []origin{{seen, "1"}}
	if local, err := netip.ParseAddr(outs[SessionSourceKey]); err == nil && !local.IsUnspecified() && local.Unmap() != seen {
		out = append(out, origin{local.Unmap(), "2"})
	}
	return out, nil
}

// coversSession rechaza un prefijo que contiene alguna IP de origen: una ruta o una subred conectada así se traga el regreso de la sesión SSH.
func coversSession(device string, p netip.Prefix, outs map[string]string) error {
	origins, err := sessionOrigins(device, outs)
	if err != nil {
		return err
	}
	for _, o := range origins {
		if p.Contains(o.addr) {
			return refuseSnippet("assist.refused.contiene_el_trafico_de_regreso", "where", p, "addr", o.addr, "what", o.what)
		}
	}
	return nil
}

func showACL(name string) string { return "show ip access-lists " + name }

// unicastIPv4 rechaza lo que no es una dirección de host utilizable (0.0.0.0, loopback, multicast, link-local, clase E, difusión).
func unicastIPv4(what, s string) error {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return cerr("assist.err.ipv4_invalid_for", "what", what, "value", s)
	}
	if a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast() || a.As4()[0] >= 240 {
		return cerr("assist.err.unicast_unusable", "what", what, "value", s)
	}
	return nil
}

// keyN devuelve las primeras n palabras de la línea (sin su `no`) si empieza con prefix (sin distinguir mayúsculas), o vacío: la clave con
// que l2Inverse empareja una línea con su reversa. Conserva las mayúsculas del resto (nombres de community, de ACL...).
func keyN(prefix string, n int) func(string) string {
	return func(line string) string {
		l := strings.TrimPrefix(squash(line), "no ")
		f := strings.Fields(l)
		if len(f) < n || !hasWordPrefix(strings.ToLower(l), prefix) {
			return ""
		}
		return strings.Join(f[:n], " ")
	}
}

func hasWordPrefix(line, prefix string) bool {
	return line == prefix || strings.HasPrefix(line, prefix+" ")
}

func ifaceEq(a, b string) bool { return strings.EqualFold(iosxe.ShortIf(a), iosxe.ShortIf(b)) }

// ---- ruta-estatica ----

var (
	ifaceNameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z-]*[0-9]+(/[0-9]+){0,3}(\.[0-9]+)?$`)
	nameWordRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)
)

// routeSpec es una ruta estática: ad vacío = la distancia de fábrica (1), que IOS no escribe.
type routeSpec struct{ net, mask, iface, nh, ad, name string }

// key es «R M [IF] [NH]», lo que identifica a la ruta en el running y en su `no`.
func (r routeSpec) key() string {
	return strings.Join(slices.DeleteFunc([]string{r.net, r.mask, r.iface, r.nh}, func(s string) bool { return s == "" }), " ")
}

func (r routeSpec) line() string {
	return strings.TrimSpace("ip route " + r.key() + ifElse(r.ad != "", " "+r.ad, "") + ifElse(r.name != "", " name "+r.name, ""))
}

// back es el `no` exacto de lo agregado: con la distancia (IOS la compara si se da) y sin el nombre.
func (r routeSpec) back() string {
	return strings.TrimSpace("no ip route " + r.key() + ifElse(r.ad != "", " "+r.ad, ""))
}

func (r routeSpec) check() error {
	if err := unicastIPv4("red", r.net); err != nil {
		return err
	}
	ones, err := maskBits(r.mask)
	if err != nil {
		return err
	}
	n := netip.MustParseAddr(r.net)
	if p, _ := n.Prefix(ones); p.Addr() != n {
		return fmt.Errorf("la red %s tiene bits de host para la máscara %s", r.net, r.mask)
	}
	if r.nh == "" && r.iface == "" {
		return errors.New("indica el siguiente salto, la interfaz de salida o ambos")
	}
	if r.nh != "" {
		if err := unicastIPv4("siguiente salto", r.nh); err != nil {
			return err
		}
		if p, _ := n.Prefix(ones); p.Contains(netip.MustParseAddr(r.nh)) {
			return fmt.Errorf("el siguiente salto %s cae dentro de la propia ruta %s/%d", r.nh, r.net, ones)
		}
	}
	if r.iface != "" && !ifaceNameRe.MatchString(r.iface) {
		return fmt.Errorf("interfaz de salida inválida %q", r.iface)
	}
	if r.ad != "" && !intIn(r.ad, 1, 255) {
		return errors.New("la distancia va de 1 a 255")
	}
	if r.name != "" && !nameWordRe.MatchString(r.name) {
		return errors.New("el nombre de la ruta es una palabra de letras, números y _ . - (hasta 32)")
	}
	return nil
}

func routeFromValues(v Values) (routeSpec, error) {
	r := routeSpec{net: v.Str("network"), mask: v.Str("mask"), iface: v.Str("exit_interface"), nh: v.Str("next_hop"), ad: v.Str("distance"), name: v.Str("name")}
	if r.ad == "1" { // la distancia de fábrica no se escribe: IOS no la muestra y el Expect no la encontraría
		r.ad = ""
	}
	return r, r.check()
}

// parseRouteLine lee una línea de apply (`ip route ...`) o de reversa (`no ip route ...`) de la lista cerrada.
func parseRouteLine(line string) (r routeSpec, neg bool, err error) {
	f := strings.Fields(line)
	if neg = len(f) > 0 && strings.EqualFold(f[0], "no"); neg {
		f = f[1:]
	}
	if len(f) < 5 || !strings.EqualFold(f[0], "ip") || !strings.EqualFold(f[1], "route") || !isIPv4s(f[2]) || !isIPv4s(f[3]) {
		return r, neg, errors.New("solo ip route RED MÁSCARA [INTERFAZ] [SALTO] [DISTANCIA] [name NOMBRE] y su no")
	}
	r.net, r.mask = f[2], f[3]
	rest := f[4:]
	if !isIPv4s(rest[0]) && !digitsOnly(rest[0]) {
		r.iface, rest = rest[0], rest[1:]
	}
	if len(rest) > 0 && isIPv4s(rest[0]) {
		r.nh, rest = rest[0], rest[1:]
	}
	if len(rest) > 0 && digitsOnly(rest[0]) {
		r.ad, rest = rest[0], rest[1:]
	}
	if len(rest) == 2 && rest[0] == "name" && !neg {
		r.name, rest = rest[1], nil
	}
	if len(rest) > 0 {
		return r, neg, errors.New("sobran argumentos (solo distancia y name)")
	}
	if err := r.check(); err != nil {
		return r, neg, err
	}
	return r, neg, nil
}

func isIPv4s(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && a.Is4()
}

func digitsOnly(s string) bool {
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

// SnippetStaticRoute agrega una ruta estática (nunca la por defecto) y la quita con su `no` exacto.
var SnippetStaticRoute = Function{
	Name:    "snippet-ruta-estatica",
	Allowed: []string{"ip route", "no ip route"},
	Check: func(line string) error {
		_, _, err := parseRouteLine(line)
		return err
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) != 1 || len(d.Rollback) != 1 {
			return errors.New("una ruta: una línea de apply y una de reversa")
		}
		a, neg, err := parseRouteLine(d.Apply[0])
		if err != nil || neg {
			return errors.New("el apply es `ip route ...`, nunca un no")
		}
		if want := a.back(); squash(d.Rollback[0]) != want {
			return fmt.Errorf("la reversa debe ser %q: el no exacto de lo agregado", want)
		}
		text, ok := d.Baseline[routeCmd]
		if !ok {
			return errors.New("falta la línea base de las rutas")
		}
		routes, ok := iosxe.ParseStaticRoutes(text)
		if !ok {
			return errors.New("la línea base de las rutas no se pudo leer")
		}
		for _, r := range routes {
			if sameRouteDest(r, a) {
				return errors.New("el equipo ya tiene una ruta a ese destino por ese salto: la reversa no la restauraría")
			}
		}
		return nil
	},
}

func sameRouteDest(r iosxe.StaticRoute, s routeSpec) bool {
	return r.Net == s.net && r.Mask == s.mask && r.NextHop == s.nh && (r.Iface == "" && s.iface == "" || ifaceEq(r.Iface, s.iface))
}

func routePre(v Values) ([]string, error) {
	if _, err := routeFromValues(v); err != nil {
		return nil, err
	}
	return []string{routeCmd, showUsersCmd}, nil
}

func routePlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	s, err := routeFromValues(v)
	if err != nil {
		return DevicePlan{}, err
	}
	text, ok := outs[routeCmd]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", routeCmd)
	}
	routes, ok := iosxe.ParseStaticRoutes(text)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", routeCmd, "device", device)
	}
	ones, _ := maskBits(s.mask)
	if err := coversSession(device, netip.PrefixFrom(netip.MustParseAddr(s.net), ones), outs); err != nil {
		return DevicePlan{}, err
	}
	var feats []l2Feature
	exists := false
	for _, r := range routes {
		if !sameRouteDest(r, s) {
			continue
		}
		if exists = true; r.Distance != s.ad || r.Name != s.name || len(r.Other) > 0 {
			return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_una_ruta_a", "device", device, "net", s.net+"/"+s.mask)
		}
	}
	if !exists {
		feats = []l2Feature{{apply: s.line(), back: s.back(), exp: Expect{Line: s.key(), Present: true, Column: "static-route"}}}
	}
	return assembleL2(device, SnippetStaticRoute, []string{routeCmd, showUsersCmd}, []l2Scope{{baseCmd: routeCmd, baseText: text, post: []string{routeCmd}, feats: feats}})
}

// l3ColumnMatch evalúa las condiciones de la fase 28d que no son una línea de texto: static-route (Line es «R M [IF] [NH]»), logging-host
// (Line es la IP, con `logging host IP` o `logging IP`, y opcional «transport T port N») y snmp-user (Line es «USUARIO GRUPO», de show snmp user).
func l3ColumnMatch(e Expect, text string) (match, ok bool) {
	switch e.Column {
	case "static-route":
		routes, ok := iosxe.ParseStaticRoutes(text)
		f := strings.Fields(e.Line)
		if !ok || len(f) < 3 {
			return false, false
		}
		want := routeSpec{net: f[0], mask: f[1]}
		for _, w := range f[2:] {
			if isIPv4s(w) {
				want.nh = w
			} else {
				want.iface = w
			}
		}
		return slices.ContainsFunc(routes, func(r iosxe.StaticRoute) bool { return sameRouteDest(r, want) }), true
	case "logging-host":
		c, ok := iosxe.ParseLoggingCfg(text)
		f := strings.Fields(e.Line)
		if !ok || len(f) == 0 {
			return false, false
		}
		// Solo la IP: cualquier destino con ella. Con «transport T port N»: el mismo transporte y puerto efectivos, sin importar si IOS
		// omite el puerto de fábrica en el running.
		wt, wp, wok := iosxe.LogHost{Options: f[1:]}.Transport()
		return slices.ContainsFunc(c.Hosts, func(h iosxe.LogHost) bool {
			if h.Addr != f[0] {
				return false
			}
			if len(f) == 1 {
				return true
			}
			t, p, ok := h.Transport()
			return wok && ok && t == wt && p == wp
		}), true
	case "snmp-user":
		users, ok := iosxe.ParseSNMPUsers(text)
		user, group, _ := strings.Cut(e.Line, " ")
		return ok && slices.ContainsFunc(users, func(u iosxe.SNMPUser) bool { return u.Name == user && u.Group == group }), ok
	}
	return false, false
}

// ---- loopback ----

var loopNameRe = regexp.MustCompile(`^(?i:loopback)(\d{1,10})$`)

func loopID(name string) (int, bool) {
	m := loopNameRe.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil && n <= 2147483647 && ntoa(n) == m[1]
}

// checkLoopbackAddress: IPv4 unicast, máscara contigua de /8 a /32 y, salvo en /31 y /32, ni la red ni la difusión.
func checkLoopbackAddress(addr, mask string) error {
	if err := unicastIPv4("loopback", addr); err != nil {
		return err
	}
	ones, err := maskBits(mask)
	if err != nil || ones < 8 {
		return cerr("assist.err.mask_range_loopback")
	}
	a := netip.MustParseAddr(addr)
	if p, _ := a.Prefix(ones); ones < 31 && (p.Addr() == a || lastOf(p) == a) {
		return cerr("assist.err.network_or_broadcast", "addr", addr, "ones", ones)
	}
	return nil
}

// SnippetLoopback crea una interfaz Loopback con IP y descripción opcional; la reversa la borra.
var SnippetLoopback = Function{
	Name:    "snippet-loopback",
	Allowed: []string{"interface", "no interface", "description", "ip address"},
	Check: func(line string) error {
		f := strings.Fields(line)
		switch l := strings.ToLower(line); {
		case f[0] == "interface" && len(f) == 2, f[0] == "no" && len(f) == 3 && f[1] == "interface":
			if _, ok := loopID(f[len(f)-1]); !ok {
				return cerr("assist.err.single_loopback")
			}
		case strings.HasPrefix(l, "ip address ") && len(f) == 4:
			return checkLoopbackAddress(f[2], f[3])
		case strings.HasPrefix(l, "description"):
			return descOK(strings.TrimSpace(line[len("description"):]))
		default:
			return cerr("assist.err.loopback_form")
		}
		return nil
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) == 0 || !strings.HasPrefix(strings.ToLower(d.Apply[0]), "interface ") {
			return cerr("assist.err.apply_starts_loopback")
		}
		name := strings.Fields(d.Apply[0])[1]
		for _, l := range d.Apply[1:] {
			if lw := strings.ToLower(l); strings.HasPrefix(lw, "interface ") || strings.HasPrefix(lw, "no ") {
				return cerr("assist.err.apply_single_interface_no_remove")
			}
		}
		if len(d.Rollback) != 1 || squash(d.Rollback[0]) != "no interface "+name {
			return cerr("assist.err.rollback_loopback_only", "port", name)
		}
		return nil
	},
}

func loopName(v Values) string { return "Loopback" + v.Str("number") }

func loopPre(v Values) ([]string, error) {
	if err := checkLoopbackAddress(v.Str("address"), v.Str("mask")); err != nil {
		return nil, err
	}
	return []string{showCfg(loopName(v)), showIPBrief, showUsersCmd}, nil
}

func loopPlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	pre, err := loopPre(v)
	if err != nil {
		return DevicePlan{}, err
	}
	name, addr, mask := loopName(v), v.Str("address"), v.Str("mask")
	text, ok := outs[pre[0]]
	brief, ok2 := outs[showIPBrief]
	if !ok || !ok2 {
		return DevicePlan{}, cerr("assist.err.outputs_missing", "command1", pre[0], "command2", showIPBrief)
	}
	rows, ok := iosxe.ParseIPBrief(brief)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_show", "device", device)
	}
	for _, r := range rows {
		if strings.EqualFold(r.Raw, name) || strings.EqualFold(r.Iface, "Lo"+v.Str("number")) {
			return DevicePlan{}, refuseSnippet("assist.refused.ya_existe_en", "name", name, "device", device)
		}
		if r.IP == addr {
			return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_la_direccion_asignada", "device", device, "addr", addr, "owner", r.Raw)
		}
	}
	if cur, exists := iosxe.ParseInterfaceConfig(text); exists {
		return DevicePlan{}, refuseSnippet("assist.refused.ya_existe_en_configuracion_de", "name", name, "device", device, "cur", cur.Name)
	} else if !strings.Contains(text, "% Invalid input") && !strings.Contains(text, "not found") {
		return DevicePlan{}, refuseSnippet("assist.refused.la_captura_de_no_es", "port", name)
	}
	ones, _ := maskBits(mask)
	subnet, _ := netip.MustParseAddr(addr).Prefix(ones)
	if err := coversSession(device, subnet, outs); err != nil {
		return DevicePlan{}, err
	}
	dp := DevicePlan{Device: device, Pre: pre, Post: []string{showCfg(name)}, Baseline: map[string]string{showCfg(name): text}, Rollback: []string{"no interface " + name}}
	dp.Apply = []string{"interface " + name}
	ex := func(l string) { dp.Expect = append(dp.Expect, Expect{Command: showCfg(name), Line: l, Present: true}) }
	if v.Has("description") {
		dp.Apply = append(dp.Apply, "description "+v.Str("description"))
		ex("description " + v.Str("description"))
	}
	dp.Apply = append(dp.Apply, "ip address "+addr+" "+mask)
	ex("ip address " + addr + " " + mask)
	if err := Validate(Plan{Function: SnippetLoopback.Name, Devices: []DevicePlan{dp}}, SnippetLoopback); err != nil {
		return DevicePlan{}, err
	}
	return dp, nil
}

// ---- helper-address ----

var routedIfaceRe = regexp.MustCompile(`(?i)^(vlan\d{1,4}|(port-channel|po|gigabitethernet|tengigabitethernet|fastethernet|twentyfivegige|fortygigabitethernet|hundredgige|ethernet|gi|te|fa|twe|fo|hu|eth)\d+(/\d+){0,3}(\.\d+)?)$`)

func isVlanIf(n string) bool { return strings.HasPrefix(strings.ToLower(n), "vlan") }

// SnippetHelper agrega un ip helper-address a una interfaz de capa 3 (SVI, puerto ruteado, Port-channel o subinterfaz).
var SnippetHelper = Function{
	Name:    "snippet-helper-address",
	Allowed: []string{"interface", "ip helper-address", "no ip helper-address"},
	Check: func(line string) error {
		f := strings.Fields(line)
		switch {
		case f[0] == "interface" && len(f) == 2:
			if !routedIfaceRe.MatchString(f[1]) {
				return errors.New("solo una SVI, un puerto físico, un Port-channel o una subinterfaz")
			}
		case f[0] == "ip" && len(f) == 3, f[0] == "no" && len(f) == 4:
			return unicastIPv4("helper", f[len(f)-1])
		default:
			return errors.New("solo interface X, ip helper-address A y su no")
		}
		return nil
	},
	CheckDevice: l2Inverse(keyN("ip helper-address", 3), ifaceBase),
}

func helperPre(v Values) ([]string, error) {
	n := v.Str("interface")
	if !routedIfaceRe.MatchString(n) {
		return nil, cerr("assist.err.not_svi_or_port", "port", n)
	}
	if err := unicastIPv4("helper", v.Str("address")); err != nil {
		return nil, err
	}
	pre := []string{showCfg(n)}
	if !isVlanIf(n) && !strings.Contains(n, ".") { // una SVI y una subinterfaz siempre son de capa 3
		pre = append(pre, showSwitchport(n))
	}
	return pre, nil
}

func helperPlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	pre, err := helperPre(v)
	if err != nil {
		return DevicePlan{}, err
	}
	n, addr := v.Str("interface"), v.Str("address")
	text, ok := outs[pre[0]]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", pre[0])
	}
	cur, ok := iosxe.ParseInterfaceConfig(text)
	switch {
	case !ok:
		return DevicePlan{}, refuseSnippet("assist.refused.no_existe_en_o_no", "port", n, "device", device)
	case !ifaceEq(cur.Name, n):
		return DevicePlan{}, cerr("assist.err.capture_mismatch", "port", n)
	case cur.ChannelGroup:
		return DevicePlan{}, refuseSnippet("assist.refused.es_miembro_de_un_canal2", "port", n)
	}
	if len(pre) > 1 {
		sw, ok := outs[pre[1]]
		if !ok {
			return DevicePlan{}, cerr("assist.err.output_missing", "command", pre[1])
		}
		if _, l2 := iosxe.ParseSwitchportMode(sw); l2 {
			return DevicePlan{}, refuseSnippet("assist.refused.es_un_puerto_de_capa", "port", n)
		}
	}
	var feats []l2Feature
	exists := false
	for _, h := range iosxe.ParseHelpers(cur) {
		if h.Addr == addr {
			if exists = true; len(h.Options) > 0 {
				return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_el_helper_con", "port", n, "addr", addr, "options", strings.Join(h.Options, " "))
			}
		}
	}
	if !exists {
		line := "ip helper-address " + addr
		feats = []l2Feature{{apply: line, back: "no " + line, exp: Expect{Line: line, Present: true}}}
	}
	return assembleL2(device, SnippetHelper, pre, []l2Scope{{header: "interface " + n, baseCmd: showCfg(n), baseText: text, post: []string{showCfg(n)}, feats: feats}})
}

// ---- ntp-server ----

// SnippetNTP agrega un servidor NTP (con prefer opcional); la reversa es su `no`.
var SnippetNTP = Function{
	Name:    "snippet-ntp-server",
	Allowed: []string{"ntp server"},
	AllowNo: true,
	Scrub:   true, // sus lecturas traen las llaves NTP del equipo
	Check: func(line string) error {
		f := strings.Fields(line)
		switch {
		case f[0] == "ntp" && (len(f) == 3 || len(f) == 4 && f[3] == "prefer"):
		case f[0] == "no" && len(f) == 4:
		default:
			return cerr("assist.err.ntp_form")
		}
		return unicastIPv4("servidor NTP", f[len(f)-1-ifElseInt(f[len(f)-1] == "prefer", 1, 0)])
	},
	CheckDevice: l2Inverse(keyN("ntp server", 3), func(string) string { return ntpCmd }),
}

func ifElseInt(c bool, a, b int) int {
	if c {
		return a
	}
	return b
}

func ntpPre(v Values) ([]string, error) {
	if err := unicastIPv4("servidor NTP", v.Str("address")); err != nil {
		return nil, err
	}
	return []string{ntpCmd}, nil
}

func ntpPlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	if _, err := ntpPre(v); err != nil {
		return DevicePlan{}, err
	}
	text, ok := outs[ntpCmd]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", ntpCmd)
	}
	servers, ok := iosxe.ParseNTPServers(text)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", ntpCmd, "device", device)
	}
	addr, prefer := v.Str("address"), v.Bool("prefer")
	var feats []l2Feature
	exists := false
	for _, s := range servers {
		if s.Vrf != "" || s.Addr != addr {
			continue
		}
		if exists = true; !slices.Equal(s.Options, ifElseSlice(prefer, []string{"prefer"})) {
			return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_el_servidor_ntp", "device", device, "addr", addr, "options", strings.Join(s.Options, " "))
		}
	}
	if !exists {
		line := "ntp server " + addr + ifElse(prefer, " prefer", "")
		feats = []l2Feature{{apply: line, back: "no ntp server " + addr, exp: Expect{Line: line, Present: true}}}
	}
	return assembleL2(device, SnippetNTP, []string{ntpCmd}, []l2Scope{{baseCmd: ntpCmd, baseText: text, post: []string{ntpCmd}, feats: feats}})
}

func ifElseSlice(c bool, a []string) []string {
	if c {
		return a
	}
	return nil
}

// ---- logging-host ----

var logLevels = []string{"emergencies", "alerts", "critical", "errors", "warnings", "notifications", "informational", "debugging"}

// loggingKey emparenta un destino (en sus dos formas, `logging host IP` y `logging IP`) y el nivel de trap con su reversa.
func loggingKey(line string) string {
	f := strings.Fields(strings.TrimPrefix(squash(line), "no "))
	switch {
	case len(f) >= 3 && f[0] == "logging" && f[1] == "host":
		return "logging host " + f[2]
	case len(f) >= 2 && f[0] == "logging" && f[1] == "trap":
		return "logging trap"
	case len(f) >= 2 && f[0] == "logging" && isIPv4s(f[1]):
		return "logging host " + f[1]
	}
	return ""
}

// SnippetLogging agrega un destino de syslog y, si se pide, fija el nivel de trap.
var SnippetLogging = Function{
	Name:    "snippet-logging-host",
	Allowed: []string{"logging host", "logging trap"},
	AllowNo: true,
	Check: func(line string) error {
		f := strings.Fields(line)
		neg := f[0] == "no"
		if neg {
			f = f[1:]
		}
		switch {
		case len(f) == 3 && f[1] == "host":
			return unicastIPv4("destino de syslog", f[2])
		case len(f) == 7 && f[1] == "host": // logging host IP transport udp|tcp port N, nada más (ni beep ni opciones extra)
			if _, _, ok := (iosxe.LogHost{Options: f[3:]}).Transport(); !ok {
				return errors.New("solo logging host A transport udp|tcp port N (1-65535)")
			}
			return unicastIPv4("destino de syslog", f[2])
		case len(f) == 3 && f[1] == "trap" && !neg && slices.Contains(logLevels, f[2]):
		case len(f) == 2 && f[1] == "trap" && neg:
		default:
			return errors.New("solo logging host A, logging trap NIVEL y su no")
		}
		return nil
	},
	// El nivel que el equipo no tenía vuelve al de fábrica (invisible): `no logging trap` se queda en el running y apaga el syslog.
	CheckDevice: func(d DevicePlan) error {
		if err := loggingInverse(d); err != nil {
			return err
		}
		// Un destino con transporte y puerto se quita con su `no` completo: el corto no distingue cuál de los destinos de la IP.
		for _, l := range d.Apply {
			if f := strings.Fields(l); len(f) == 7 && !slices.ContainsFunc(d.Rollback, func(r string) bool { return squash(r) == "no "+squash(l) }) {
				return fmt.Errorf("la reversa de %q debe ser %q", l, "no "+squash(l))
			}
		}
		return nil
	},
}

var loggingInverse = l2InverseDef(loggingKey, func(string) string { return loggingCmd }, func(k string) string {
	return ifElse(k == "logging trap", "logging trap informational", "")
})

// loggingSpec es el destino que se pide: la línea de apply, el transporte y puerto efectivos, y la cola de la línea («transport T port N»,
// vacía si no se pidió ni transporte ni puerto, o si el resultado es udp 514: el `logging host IP` de siempre). Si solo viene el puerto el transporte es udp; si
// solo viene el transporte el puerto es el de fábrica (udp 514, tcp 601). Supuesto sin validar en laboratorio.
func loggingSpec(v Values) (apply, opts, transport string, port int) {
	transport, port = v.Str("transport"), v.Int("port")
	if transport == "" && port == 0 {
		return "logging host " + v.Str("address"), "", "udp", 514
	}
	if transport == "" {
		transport = "udp"
	}
	if port == 0 {
		port = ifElseInt(transport == "tcp", 601, 514)
	}
	if transport == "udp" && port == 514 { // la forma probada en el equipo; no depende de cómo IOS normalice `transport udp port 514`
		return "logging host " + v.Str("address"), "", "udp", 514
	}
	opts = fmt.Sprintf("transport %s port %d", transport, port)
	return "logging host " + v.Str("address") + " " + opts, opts, transport, port
}

func loggingPre(v Values) ([]string, error) {
	if err := unicastIPv4("destino de syslog", v.Str("address")); err != nil {
		return nil, err
	}
	if t, p := v.Str("transport"), v.Int("port"); t != "" && t != "udp" && t != "tcp" || p < 0 || p > 65535 || v.Has("port") && p == 0 {
		return nil, cerr("assist.err.logging_transport")
	}
	return []string{loggingCmd}, nil
}

func loggingPlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	if _, err := loggingPre(v); err != nil {
		return DevicePlan{}, err
	}
	text, ok := outs[loggingCmd]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", loggingCmd)
	}
	cfg, ok := iosxe.ParseLoggingCfg(text)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", loggingCmd, "device", device)
	}
	addr := v.Str("address")
	apply, opts, wantT, wantP := loggingSpec(v)
	var feats []l2Feature
	exists := false
	for _, h := range cfg.Hosts {
		if h.Addr != addr {
			continue
		}
		// La misma IP con otro transporte, puerto u opciones: la llave del plan (loggingKey) es por IP, un solo destino por IP.
		if t, p, ok := h.Transport(); !ok || t != wantT || p != wantP {
			return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_un_destino_de", "device", device, "addr", addr, "existing", strings.TrimSpace("logging host "+addr+" "+strings.Join(h.Options, " ")))
		}
		exists = true
	}
	if !exists {
		feats = append(feats, l2Feature{apply: apply, back: "no " + apply, exp: Expect{Line: strings.TrimSpace(addr + " " + opts), Present: true, Column: "logging-host"}})
	}
	if level := v.Str("level"); level != "" {
		if cfg.Trap != "" && !slices.Contains(logLevels, cfg.Trap) {
			return DevicePlan{}, refuseSnippet("assist.refused.tiene_logging_trap_que_la", "device", device, "trap", cfg.Trap)
		}
		if cfg.NoTrap && cfg.Trap != "" {
			return DevicePlan{}, refuseSnippet("assist.refused.trae_no_logging_trap_y", "device", device, "trap", cfg.Trap)
		}
		eff, back := "informational", "logging trap informational"
		switch {
		case cfg.NoTrap:
			eff, back = "none", "no logging trap" // se restaura tal cual estaba
		case cfg.Trap != "":
			eff, back = cfg.Trap, "logging trap "+cfg.Trap
		}
		if level != eff {
			f := l2Feature{apply: "logging trap " + level, back: back}
			f.exp = Expect{Line: f.apply, Present: true}
			if level == "informational" { // el nivel de fábrica no sale en el running-config
				f.exp = Expect{Line: "logging trap", Present: false, Prefix: true}
			}
			feats = append(feats, f)
		}
	}
	return assembleL2(device, SnippetLogging, []string{loggingCmd}, []l2Scope{{baseCmd: loggingCmd, baseText: text, post: []string{loggingCmd}, feats: feats}})
}

// ---- snmp-community ----

var communityRe = regexp.MustCompile(`^[\x21-\x7e]{4,32}$`)

func checkCommunity(c string) error {
	if !communityRe.MatchString(c) || strings.Contains(c, "@") || strings.Contains(c, "?") {
		return cerr("assist.err.community_format") // sin citarla
	}
	return nil
}

// SnippetSNMPCommunity agrega una community de solo lectura, con ACL opcional. RW nunca.
var SnippetSNMPCommunity = Function{
	Name:    "snippet-snmp-community",
	Allowed: []string{"snmp-server community"},
	AllowNo: true,
	Scrub:   true,
	Check: func(line string) error {
		f := strings.Fields(line)
		neg := f[0] == "no"
		if neg {
			f = f[1:]
		}
		if len(f) < 3 || checkCommunity(f[2]) != nil {
			return cerr("assist.err.community_line_form")
		}
		switch {
		case neg && len(f) == 3:
		case !neg && (len(f) == 4 || len(f) == 5) && f[3] == "RO" && (len(f) == 4 || aclNameRe.MatchString(f[4])):
		default:
			return cerr("assist.err.community_form")
		}
		return nil
	},
	CheckDevice: l2Inverse(keyN("snmp-server community", 3), func(string) string { return snmpCommCmd }),
}

func snmpCommPre(v Values) ([]string, error) {
	if err := checkCommunity(v.Str("community")); err != nil {
		return nil, err
	}
	pre := []string{snmpCommCmd}
	if acl := v.Str("acl"); acl != "" {
		pre = append(pre, showACL(acl))
	}
	return pre, nil
}

func snmpCommPlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	pre, err := snmpCommPre(v)
	if err != nil {
		return DevicePlan{}, err
	}
	name, acl := v.Str("community"), v.Str("acl")
	text, ok := outs[snmpCommCmd]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", snmpCommCmd)
	}
	comms, ok := iosxe.ParseSNMPCommunities(text)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", snmpCommCmd, "device", device)
	}
	if slices.ContainsFunc(comms, func(c iosxe.SNMPCommunity) bool { return c.Name == name }) { // jamás se cita la community
		return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_una_community_con", "device", device)
	}
	if acl != "" {
		out, ok := outs[showACL(acl)]
		if !ok {
			return DevicePlan{}, cerr("assist.err.output_missing", "command", showACL(acl))
		}
		lists, ok := iosxe.ParseAccessLists(out)
		if !ok {
			return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en6", "acl", showACL(acl), "device", device)
		}
		if !slices.ContainsFunc(lists, func(l iosxe.AccessList) bool { return l.Name == acl }) {
			return DevicePlan{}, refuseSnippet("assist.refused.la_acl_no_existe_en", "acl", acl, "device", device)
		}
	}
	line := "snmp-server community " + name + " RO" + ifElse(acl != "", " "+acl, "")
	feats := []l2Feature{{apply: line, back: "no snmp-server community " + name, exp: Expect{Line: line, Present: true}}}
	return assembleG(device, SnippetSNMPCommunity, pre, []l2Scope{{baseCmd: snmpCommCmd, baseText: text, post: []string{snmpCommCmd}, feats: feats}}, nil, []string{name})
}

// ---- banner-motd ----

// SnippetBanner pone un banner motd de una línea. Escribe el delimitador `#` (que el texto no puede llevar) y IOS lo muestra como ^C.
var SnippetBanner = Function{
	Name:    "snippet-banner-motd",
	Allowed: []string{"banner motd", "no banner motd"},
	Check: func(line string) error {
		if squash(line) == "no banner motd" {
			return nil
		}
		t, ok := strings.CutPrefix(line, "banner motd #")
		t, ok2 := strings.CutSuffix(t, "#")
		if !ok || !ok2 || t == "" || len(t) > maxText || strings.ContainsAny(t, "#^") {
			return cerr("assist.err.banner_form")
		}
		return nil
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) != 1 || len(d.Rollback) != 1 || !strings.HasPrefix(d.Apply[0], "banner motd #") {
			return cerr("assist.err.banner_lines")
		}
		old, ok := iosxe.ParseBannerMOTD(d.Baseline[bannerCmd])
		switch {
		case !ok || old.Multi:
			return cerr("assist.err.banner_unreadable")
		case !old.Present:
			if d.Rollback[0] != "no banner motd" {
				return cerr("assist.err.banner_none_before")
			}
		case strings.ContainsAny(old.Text, "#^") || d.Rollback[0] != "banner motd #"+old.Text+"#":
			return cerr("assist.err.rollback_banner")
		}
		return nil
	},
}

func bannerPre(Values) ([]string, error) { return []string{bannerCmd}, nil }

func bannerPlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	text, ok := outs[bannerCmd]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", bannerCmd)
	}
	old, ok := iosxe.ParseBannerMOTD(text)
	switch {
	case !ok:
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", bannerCmd, "device", device)
	case old.Multi:
		return DevicePlan{}, refuseSnippet("assist.refused.tiene_un_banner_motd_de", "device", device)
	case strings.ContainsAny(old.Text, "#^"):
		return DevicePlan{}, refuseSnippet("assist.refused.el_banner_motd_actual_de", "device", device)
	}
	var feats []l2Feature
	if t := v.Str("text"); !old.Present || old.Text != t {
		feats = []l2Feature{{apply: "banner motd #" + t + "#", back: ifElse(old.Present, "banner motd #"+old.Text+"#", "no banner motd"),
			exp: Expect{Line: "banner motd ^C" + t + "^C", Present: true}}}
	}
	return assembleL2(device, SnippetBanner, []string{bannerCmd}, []l2Scope{{baseCmd: bannerCmd, baseText: text, post: []string{bannerCmd}, feats: feats}})
}

// ---- snmpv3-usuario ----

var snmpPassRe = regexp.MustCompile(`^[\x21-\x7e]{8,64}$`)

// v3Parts descompone una línea de la lista cerrada de snmpv3-usuario: group (`snmp-server group G v3 priv`) o user
// (`snmp-server user U G v3 auth sha A priv aes 128 P`), con o sin `no` (en la reversa el usuario lleva solo `U G v3`).
type v3Parts struct {
	kind, user, group string
	neg               bool
}

func parseV3Line(line string) (v3Parts, error) {
	f := strings.Fields(line)
	p := v3Parts{}
	if p.neg = len(f) > 0 && f[0] == "no"; p.neg {
		f = f[1:]
	}
	bad := errors.New("solo snmp-server group G v3 priv, snmp-server user U G v3 auth sha A priv aes 128 P y su no (sin `no`, A y P de 8 a 64 caracteres)")
	if len(f) < 5 || f[0] != "snmp-server" {
		return p, bad
	}
	switch {
	case f[1] == "group" && len(f) == 5 && f[3] == "v3" && f[4] == "priv" && nameWordRe.MatchString(f[2]):
		p.kind, p.group = "group", f[2]
	case f[1] == "user" && p.neg && len(f) == 5 && f[4] == "v3" && nameWordRe.MatchString(f[2]) && nameWordRe.MatchString(f[3]):
		p.kind, p.user, p.group = "user", f[2], f[3]
	case f[1] == "user" && !p.neg && len(f) == 12 && f[4] == "v3" && f[5] == "auth" && f[6] == "sha" && f[8] == "priv" && f[9] == "aes" && f[10] == "128" &&
		nameWordRe.MatchString(f[2]) && nameWordRe.MatchString(f[3]) && snmpPassRe.MatchString(f[7]) && snmpPassRe.MatchString(f[11]):
		p.kind, p.user, p.group = "user", f[2], f[3]
	default:
		return p, bad
	}
	return p, nil
}

// SnippetSNMPv3 crea un usuario SNMPv3 authPriv (SHA y AES-128) y, si no existe, su grupo.
var SnippetSNMPv3 = Function{
	Name:    "snippet-snmpv3-usuario",
	Allowed: []string{"snmp-server group", "snmp-server user"},
	AllowNo: true,
	Scrub:   true,
	Check: func(line string) error {
		_, err := parseV3Line(line)
		return err
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) < 1 || len(d.Apply) > 2 {
			return errors.New("un usuario SNMPv3 (y, si el grupo no existe, su grupo)")
		}
		u, err := parseV3Line(d.Apply[len(d.Apply)-1])
		if err != nil || u.kind != "user" || u.neg {
			return errors.New("el último apply es el `snmp-server user`")
		}
		mkGroup := len(d.Apply) == 2
		wantBack := []string{"no snmp-server user " + u.user + " " + u.group + " v3"}
		if mkGroup {
			g, err := parseV3Line(d.Apply[0])
			if err != nil || g.kind != "group" || g.neg || g.group != u.group {
				return errors.New("el primer apply es el `snmp-server group` del usuario")
			}
			wantBack = append(wantBack, "no snmp-server group "+u.group+" v3 priv")
		}
		if len(d.Rollback) != len(wantBack) {
			return fmt.Errorf("la reversa son %d líneas: %s", len(wantBack), strings.Join(wantBack, ", "))
		}
		for i, w := range wantBack {
			if squash(d.Rollback[i]) != w {
				return fmt.Errorf("la reversa debe ser %q en ese lugar", w)
			}
		}
		users, ok1 := iosxe.ParseSNMPUsers(d.Baseline[snmpUserCmd])
		groups, ok2 := iosxe.ParseSNMPGroups(d.Baseline[snmpGroupCmd])
		if _, has := d.Baseline[snmpUserCmd]; !has || !ok1 || !ok2 {
			return errors.New("falta la línea base de los usuarios y los grupos SNMP, o no se pudo leer")
		}
		if slices.ContainsFunc(users, func(x iosxe.SNMPUser) bool { return x.Name == u.user }) {
			return errors.New("el equipo ya tiene ese usuario: la reversa no lo restauraría")
		}
		priv := slices.ContainsFunc(groups, func(g iosxe.SNMPGroup) bool { return g.Name == u.group && g.Version == "v3" && g.Level == "priv" })
		if mkGroup == priv {
			return errors.New("el grupo se crea solo si no existía como v3 priv (y la reversa solo borra el que creó)")
		}
		return nil
	},
}

func snmpv3Pre(Values) ([]string, error) { return []string{snmpUserCmd, snmpGroupCmd}, nil }

func snmpv3Plan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	userText, ok1 := outs[snmpUserCmd]
	groupText, ok2 := outs[snmpGroupCmd]
	if !ok1 || !ok2 {
		return DevicePlan{}, cerr("assist.err.outputs_missing", "command1", snmpUserCmd, "command2", snmpGroupCmd)
	}
	users, ok1 := iosxe.ParseSNMPUsers(userText)
	groups, ok2 := iosxe.ParseSNMPGroups(groupText)
	if !ok1 || !ok2 {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_o", "command1", snmpUserCmd, "command2", snmpGroupCmd, "device", device)
	}
	user, group := v.Str("user"), v.Str("group")
	if slices.ContainsFunc(users, func(u iosxe.SNMPUser) bool { return u.Name == user }) {
		return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_el_usuario_snmpv3", "device", device, "user", user)
	}
	groupExists := false
	for _, g := range groups {
		if g.Name != group || g.Version != "v3" {
			continue
		}
		if g.Level != "priv" {
			return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_el_grupo_v3", "device", device, "group", group, "level", g.Level)
		}
		groupExists = true
	}
	userLine := "snmp-server user " + user + " " + group + " v3 auth sha " + v.Str("auth_password") + " priv aes 128 " + v.Str("priv_password")
	var feats []l2Feature
	groupLine := "snmp-server group " + group + " v3 priv"
	if !groupExists {
		feats = append(feats, l2Feature{apply: groupLine, back: "no " + groupLine, exp: Expect{Line: groupLine, Present: true}})
	}
	feats = append(feats, l2Feature{apply: userLine, back: "no snmp-server user " + user + " " + group + " v3", exp: Expect{Line: groupLine, Present: true, Prefix: true}})
	return assembleG(device, SnippetSNMPv3, []string{snmpUserCmd, snmpGroupCmd}, []l2Scope{{
		baseCmd: snmpGroupCmd, baseText: groupText, post: []string{snmpGroupCmd, snmpUserCmd}, base: map[string]string{snmpUserCmd: userText},
		expect: []Expect{{Command: snmpUserCmd, Line: user + " " + group, Present: true, Column: "snmp-user"}}, feats: feats,
	}}, []i18n.Text{note("assist.note.snmpv3")},
		[]string{v.Str("auth_password"), v.Str("priv_password")})
}

// ---- vty-acl ----

var aclNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func vtyHead(lo, hi int) string {
	if lo == hi {
		return "line vty " + ntoa(lo)
	}
	return "line vty " + ntoa(lo) + " " + ntoa(hi)
}

// parseVtyHead lee `line vty A [B]` con 0 <= A <= B <= 15.
func parseVtyHead(line string) (lo, hi int, ok bool) {
	f := strings.Fields(line)
	if len(f) < 3 || len(f) > 4 || !strings.EqualFold(f[0], "line") || !strings.EqualFold(f[1], "vty") || !intIn(f[2], 0, 15) || len(f) == 4 && !intIn(f[3], 0, 15) {
		return 0, 0, false
	}
	lo, _ = strconv.Atoi(f[2])
	hi = lo
	if len(f) == 4 {
		hi, _ = strconv.Atoi(f[3])
	}
	return lo, hi, lo <= hi
}

// parseAccessClassIn lee `[no] access-class ACL in` y devuelve la ACL.
func parseAccessClassIn(line string) (acl string, neg, ok bool) {
	f := strings.Fields(line)
	if neg = len(f) > 0 && f[0] == "no"; neg {
		f = f[1:]
	}
	if len(f) != 3 || f[0] != "access-class" || f[2] != "in" || !aclNameRe.MatchString(f[1]) {
		return "", neg, false
	}
	return f[1], neg, true
}

// SnippetVtyACL pone un `access-class ACL in` en los bloques vty; la reversa lo quita de los mismos bloques en orden inverso.
var SnippetVtyACL = Function{
	Name:    "snippet-vty-acl",
	Allowed: []string{"line vty", "access-class", "no access-class"},
	Scrub:   true, // sus lecturas traen la contraseña de las líneas vty
	Check: func(line string) error {
		if strings.HasPrefix(strings.ToLower(line), "line ") {
			if _, _, ok := parseVtyHead(line); !ok {
				return errors.New("solo line vty A [B] con 0 <= A <= B <= 15")
			}
			return nil
		}
		if _, _, ok := parseAccessClassIn(line); !ok {
			return errors.New("solo access-class ACL in y no access-class ACL in")
		}
		return nil
	},
	CheckDevice: func(d DevicePlan) error {
		if len(d.Apply) == 0 || len(d.Apply)%2 != 0 || len(d.Rollback) != len(d.Apply) {
			return errors.New("cada bloque vty lleva su encabezado y su access-class, y la reversa los mismos")
		}
		blocks, ok := iosxe.ParseVtyBlocks(d.Baseline[vtyCmd])
		if _, has := d.Baseline[vtyCmd]; !has || !ok {
			return errors.New("falta la línea base de las líneas vty, o no se pudo leer")
		}
		var acl string
		n := len(d.Apply) / 2
		for i := 0; i < n; i++ {
			lo, hi, ok1 := parseVtyHead(d.Apply[2*i])
			a, neg, ok2 := parseAccessClassIn(d.Apply[2*i+1])
			if !ok1 || !ok2 || neg || (acl != "" && a != acl) {
				return errors.New("el apply son pares `line vty A B` + `access-class ACL in` de una sola ACL")
			}
			acl = a
			rb := d.Rollback[2*(n-1-i):]
			if squash(rb[0]) != vtyHead(lo, hi) || squash(rb[1]) != "no access-class "+acl+" in" {
				return fmt.Errorf("la reversa debe quitar el access-class de %s, en orden inverso", vtyHead(lo, hi))
			}
			if !slices.ContainsFunc(blocks, func(b iosxe.VtyBlock) bool { return b.Lo == lo && b.Hi == hi && !b.HasAccessIn }) {
				return fmt.Errorf("%s no está en la línea base o ya tiene un access-class in: la reversa no lo restauraría", vtyHead(lo, hi))
			}
		}
		return nil
	},
}

func vtyRange(v Values) (lo, hi int, err error) {
	if _, err := fmt.Sscanf(v.Str("lines"), "%d %d", &lo, &hi); err != nil || lo != 0 || (hi != 4 && hi != 15) {
		return 0, 0, cerr("assist.err.vty_lines")
	}
	return lo, hi, nil
}

func vtyPre(v Values) ([]string, error) {
	if _, _, err := vtyRange(v); err != nil {
		return nil, err
	}
	return []string{vtyCmd, showACL(v.Str("acl")), showUsersCmd}, nil
}

// aclAllows dice si la ACL estándar deja entrar a ip: la primera regla que lo cubre decide y, si ninguna, el deny implícito.
func aclAllows(l iosxe.AccessList, ip netip.Addr) bool {
	for _, e := range l.Entries {
		if e.Matches(ip) {
			return e.Action == "permit"
		}
	}
	return false
}

func vtyPlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	pre, err := vtyPre(v)
	if err != nil {
		return DevicePlan{}, err
	}
	lo, hi, _ := vtyRange(v)
	acl := v.Str("acl")
	// Las IP de origen deciden si la ACL te deja fuera: la que el equipo ve y la local de la app si difiere. Si no se saben, se rechaza.
	origins, err := sessionOrigins(device, outs)
	if err != nil {
		return DevicePlan{}, err
	}
	for _, o := range origins {
		if !o.addr.Is4() {
			return DevicePlan{}, refuseSnippet("assist.refused.es_y_una_acl_estandar", "addr", o.addr, "what", o.what)
		}
	}
	aclText, ok := outs[pre[1]]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", pre[1])
	}
	lists, ok := iosxe.ParseAccessLists(aclText)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", pre[1], "device", device)
	}
	i := slices.IndexFunc(lists, func(l iosxe.AccessList) bool { return l.Name == acl })
	switch {
	case i < 0:
		return DevicePlan{}, refuseSnippet("assist.refused.la_acl_no_existe_en2", "acl", acl, "device", device)
	case !lists[i].Standard:
		return DevicePlan{}, refuseSnippet("assist.refused.la_acl_es_extendida_para", "acl", acl)
	}
	for _, o := range origins {
		if !aclAllows(lists[i], o.addr) {
			return DevicePlan{}, refuseSnippet("assist.refused.la_acl_no_permite_te", "acl", acl, "what", o.what, "addr", o.addr)
		}
	}
	vtyText, ok := outs[vtyCmd]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", vtyCmd)
	}
	blocks, ok := iosxe.ParseVtyBlocks(vtyText)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", vtyCmd, "device", device)
	}
	// Los bloques que cubren exactamente el rango pedido: ninguno puede quedar partido, y no puede haber huecos.
	var sel []iosxe.VtyBlock
	for _, b := range blocks {
		switch {
		case b.Hi < lo || b.Lo > hi:
		case b.Lo < lo || b.Hi > hi:
			return DevicePlan{}, refuseSnippet("assist.refused.tiene_que_desborda_las_lineas", "device", device, "block", vtyHead(b.Lo, b.Hi), "lo", lo, "hi", hi)
		default:
			sel = append(sel, b)
		}
	}
	slices.SortFunc(sel, func(a, b iosxe.VtyBlock) int { return a.Lo - b.Lo })
	next := lo
	for _, b := range sel {
		if b.Lo != next {
			return DevicePlan{}, refuseSnippet("assist.refused.no_tiene_un_bloque_para", "device", device, "next", next, "hi", b.Lo-1)
		}
		next = b.Hi + 1
	}
	if next != hi+1 {
		return DevicePlan{}, refuseSnippet("assist.refused.no_tiene_un_bloque_para", "device", device, "next", next, "hi", hi)
	}
	var scopes []l2Scope
	for _, b := range sel {
		switch {
		case b.HasAccessIn && b.AccessIn != acl:
			return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_el_access_class", "block", vtyHead(b.Lo, b.Hi), "acl", b.AccessIn)
		case b.HasAccessIn:
			continue
		}
		head := vtyHead(b.Lo, b.Hi)
		line := "access-class " + acl + " in"
		// La ACL va a la línea base solo para que el motor note, antes de aplicar, que cambió desde el plan (checkBase no la compara).
		sc := l2Scope{header: head, baseCmd: vtyCmd, baseText: vtyText, base: map[string]string{pre[1]: aclText},
			feats: []l2Feature{{apply: line, back: "no " + line, exp: Expect{Line: head + expectSep + line, Present: true, Column: "section-line"}}}}
		if len(scopes) == 0 {
			sc.post = []string{vtyCmd}
		}
		scopes = append(scopes, sc)
	}
	n := note("assist.note.vty_acl", "acl", acl, "ip1", origins[0].addr, "what1", origins[0].what)
	if len(origins) > 1 {
		n = note("assist.note.vty_acl_two", "acl", acl, "ip1", origins[0].addr, "what1", origins[0].what, "ip2", origins[1].addr, "what2", origins[1].what)
	}
	return assembleG(device, SnippetVtyACL, pre, scopes, []i18n.Text{n}, nil)
}

func l3MgmtTemplates() []Template {
	return []Template{
		{ID: "ruta-estatica", Tech: "l3", Name: "Ruta estática", Platforms: bothPlatforms, Fn: SnippetStaticRoute,
			Fields: []Field{
				{Name: "network", Label: "Red", Type: TypeIPv4, Required: true},
				{Name: "mask", Label: "Máscara", Type: TypeIPv4Mask, Required: true, Default: "255.255.255.0", Help: "Contigua; la ruta por defecto 0.0.0.0/0 no se admite en esta plantilla."},
				{Name: "next_hop", Label: "Siguiente salto", Type: TypeIPv4, Help: "Siguiente salto, interfaz de salida o ambos."},
				{Name: "exit_interface", Label: "Interfaz de salida", Type: TypeText, Max: 40, Pattern: `^[A-Za-z][A-Za-z-]*[0-9]+(/[0-9]+){0,3}(\.[0-9]+)?$`, Help: "Por ejemplo Null0 o GigabitEthernet1/0/1."},
				{Name: "distance", Label: "Distancia administrativa", Type: TypeInt, Min: 1, Max: 255, Help: "Vacío o 1 = la de fábrica. Más alta que la dinámica hace una ruta flotante."},
				{Name: "name", Label: "Nombre", Type: TypeText, Max: 32, Pattern: `^[A-Za-z0-9_.-]+$`, Help: "Una palabra: letras, números, _ . -"},
			},
			Pre: routePre, Plan: routePlan},
		{ID: "loopback", Tech: "l3", Name: "Interfaz Loopback con dirección IP", Platforms: bothPlatforms, Fn: SnippetLoopback,
			Fields: []Field{
				{Name: "number", Label: "Número", Type: TypeInt, Required: true, Min: 0, Max: 2147483647},
				{Name: "address", Label: "Dirección IP", Type: TypeIPv4, Required: true},
				{Name: "mask", Label: "Máscara", Type: TypeIPv4Mask, Required: true, Default: "255.255.255.255", Help: "Contigua, de /8 a /32."},
				{Name: "description", Label: "Descripción", Type: TypeText, Max: 200},
			},
			Pre: loopPre, Plan: loopPlan},
		{ID: "helper-address", Tech: "l3", Name: "ip helper-address en una interfaz", Platforms: bothPlatforms, Fn: SnippetHelper,
			Fields: []Field{
				{Name: "interface", Label: "Interfaz", Type: TypeText, Required: true, Max: 40, Pattern: `^[A-Za-z][A-Za-z-]*[0-9]+(/[0-9]+){0,3}(\.[0-9]+)?$`, Help: "SVI (Vlan10), puerto ruteado, Port-channel o subinterfaz; no un puerto de capa 2."},
				{Name: "address", Label: "Servidor DHCP", Type: TypeIPv4, Required: true},
			},
			Pre: helperPre, Plan: helperPlan},
		{ID: "ntp-server", Tech: "gestion", Name: "Servidor NTP", Platforms: bothPlatforms, Fn: SnippetNTP,
			Fields: []Field{
				{Name: "address", Label: "Servidor NTP", Type: TypeIPv4, Required: true},
				{Name: "prefer", Label: "Preferido (prefer)", Type: TypeBool, Default: "false"},
			},
			Pre: ntpPre, Plan: ntpPlan},
		{ID: "logging-host", Tech: "gestion", Name: "Destino de syslog", Platforms: bothPlatforms, Fn: SnippetLogging,
			Fields: []Field{
				{Name: "address", Label: "Servidor de syslog", Type: TypeIPv4, Required: true},
				{Name: "transport", Label: "Transporte", Type: TypeChoice, Choices: []string{"udp", "tcp"}, Help: "Vacío con puerto vacío: `logging host IP` (udp 514). Con solo el puerto, el transporte es udp; con solo el transporte, el puerto de fábrica (udp 514, tcp 601)."},
				{Name: "port", Label: "Puerto", Type: TypeInt, Min: 1, Max: 65535, Help: "Para el receptor de la app (puerto alto, p. ej. 5514). Si se pide, la línea es `logging host IP transport T port N` (udp 514 se manda como `logging host IP`)."},
				{Name: "level", Label: "Nivel de trap", Type: TypeChoice, Choices: logLevels, Help: "Vacío no toca el nivel que ya tiene el equipo."},
			},
			Pre: loggingPre, Plan: loggingPlan},
		{ID: "snmp-community", Tech: "gestion", Name: "Community SNMP de solo lectura", Platforms: bothPlatforms, Fn: SnippetSNMPCommunity,
			Fields: []Field{
				{Name: "community", Label: "Community", Type: TypeSecret, Required: true, Min: 4, Max: 32, Help: "4-32 caracteres, sin espacios ni @. No se muestra en ninguna parte."},
				{Name: "acl", Label: "ACL de acceso", Type: TypeText, Max: 64, Pattern: `^[A-Za-z0-9_.-]+$`, Help: "ACL que ya exista en el equipo (nombre o número); recomendada. Solo lectura (RO): RW nunca."},
			},
			Pre: snmpCommPre, Plan: snmpCommPlan},
		{ID: "banner-motd", Tech: "gestion", Name: "Banner motd de una línea", Platforms: bothPlatforms, Fn: SnippetBanner,
			Fields: []Field{
				{Name: "text", Label: "Texto", Type: TypeText, Required: true, Min: 1, Max: 200, Pattern: `^[^#^?]+$`, Help: "Una línea de ASCII, sin # ni ^."},
			},
			Pre: bannerPre, Plan: bannerPlan},
		{ID: "snmpv3-usuario", Tech: "gestion", Name: "Usuario SNMPv3 (authPriv)", Platforms: bothPlatforms, Fn: SnippetSNMPv3,
			Fields: []Field{
				{Name: "user", Label: "Usuario", Type: TypeText, Required: true, Max: 32, Pattern: `^[A-Za-z0-9_.-]+$`},
				{Name: "group", Label: "Grupo", Type: TypeText, Required: true, Max: 32, Pattern: `^[A-Za-z0-9_.-]+$`, Help: "Si no existe se crea como v3 priv; uno existente con otro nivel se rechaza."},
				{Name: "auth", Label: "Autenticación", Type: TypeChoice, Choices: []string{"sha"}, Default: "sha"},
				{Name: "auth_password", Label: "Contraseña de autenticación", Type: TypeSecret, Required: true, Min: 8, Max: 64},
				{Name: "priv", Label: "Privacidad", Type: TypeChoice, Choices: []string{"aes 128"}, Default: "aes 128"},
				{Name: "priv_password", Label: "Contraseña de privacidad", Type: TypeSecret, Required: true, Min: 8, Max: 64},
			},
			Pre: snmpv3Pre, Plan: snmpv3Plan},
		{ID: "vty-acl", Tech: "seguridad", Name: "ACL en las líneas vty", Platforms: bothPlatforms, Fn: SnippetVtyACL,
			Fields: []Field{
				{Name: "acl", Label: "ACL estándar", Type: TypeText, Required: true, Max: 64, Pattern: `^[A-Za-z0-9_.-]+$`, Help: "Nombre o número de una ACL estándar que ya exista y permita la IP desde la que administras; si te dejaría fuera, se rechaza."},
				{Name: "lines", Label: "Líneas vty", Type: TypeChoice, Required: true, Choices: []string{"0 4", "0 15"}, Default: "0 4", Help: "Cada bloque vty del equipo dentro del rango recibe el access-class."},
			},
			Pre: vtyPre, Plan: vtyPlan},
	}
}
