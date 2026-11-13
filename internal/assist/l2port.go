package assist

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Lote L2 por puerto de la fase 28b: velocidad y duplex, storm-control, portfast y BPDU guard, port-security y la recuperación de errdisable.
// Todas arman un plan por equipo que cubre varios puertos. La reversa restaura la línea que el puerto tenía (capturada en Baseline) o
// manda el `no` exacto si no la tenía, y el motor la verifica contra esa línea base (run.go): lo que la reversa no sabría dejar
// idéntico se rechaza aquí, con el motivo.

// l2Feature es una línea de apply con su reversa y lo que se espera ver al aplicarla.
type l2Feature struct {
	apply, back string
	exp         Expect // si no trae Command, lo pone assembleG (el comando base del alcance)
}

// l2Scope es un puerto (o la configuración global, header vacío) con sus cambios.
type l2Scope struct {
	header, baseCmd, baseText string
	post                      []string          // comandos de Post que se agregan; el primero es el de baseCmd
	status                    string            // show interfaces X status: se espera que el puerto no quede inactive ni err-disabled; vacío = sin esa verificación
	base                      map[string]string // más comandos de la línea base (el estado del puerto, para ver que la reversa no lo deja err-disabled)
	expect                    []Expect          // más condiciones, ya con su Command
	feats                     []l2Feature
}

// assembleL2 arma el DevicePlan: apply en orden, reversa en orden inverso (también entre puertos), post y expect. Un alcance sin cambios no
// entra; si ninguno cambia no hay plan.
func assembleL2(device string, fn Function, pre []string, scopes []l2Scope, notes ...i18n.Text) (DevicePlan, error) {
	return assembleG(device, fn, pre, scopes, notes, nil)
}

// assembleG es assembleL2 con los secretos del plan (fase 28d): Validate los quita de sus errores, así que tienen que estar antes.
func assembleG(device string, fn Function, pre []string, scopes []l2Scope, notes []i18n.Text, secrets []string) (DevicePlan, error) {
	dp := DevicePlan{Device: device, Pre: pre, Baseline: map[string]string{}, NoteItems: notes, Secrets: secrets}
	for _, n := range notes {
		dp.Notes = append(dp.Notes, n.In(i18n.Es))
	}
	var back [][]string
	for _, sc := range scopes {
		if len(sc.feats) == 0 {
			continue
		}
		var apply, rb []string
		if sc.header != "" {
			apply, rb = []string{sc.header}, []string{sc.header}
		}
		for _, f := range sc.feats {
			apply = append(apply, f.apply)
			e := f.exp
			if e.Command == "" {
				e.Command = sc.baseCmd
			}
			dp.Expect = append(dp.Expect, e)
		}
		for i := len(sc.feats) - 1; i >= 0; i-- { // dentro del puerto la reversa también va al revés
			rb = append(rb, sc.feats[i].back)
		}
		if sc.status != "" {
			for _, bad := range []string{"inactive", "err-disabled"} {
				dp.Expect = append(dp.Expect, Expect{Command: sc.status, Line: bad, Column: "status"})
			}
		}
		dp.Expect = append(dp.Expect, sc.expect...)
		dp.Apply = append(dp.Apply, apply...)
		back = append(back, rb)
		dp.Post = append(dp.Post, sc.post...)
		dp.Baseline[sc.baseCmd] = sc.baseText
		for k, v := range sc.base {
			dp.Baseline[k] = v
		}
	}
	if len(back) == 0 {
		return DevicePlan{}, cerr("assist.err.nothing_to_change")
	}
	for i := len(back) - 1; i >= 0; i-- {
		dp.Rollback = append(dp.Rollback, back[i]...)
	}
	// Lo que la reversa no pueda restaurar rompe el plan aquí, no a mitad del cambio.
	if err := Validate(Plan{Function: fn.Name, Devices: []DevicePlan{dp}}, fn); err != nil {
		return DevicePlan{}, err
	}
	return dp, nil
}

// l2Port es un puerto capturado.
type l2Port struct {
	name, text, switchport string
	cur                    iosxe.InterfaceConfig
	l2                     iosxe.L2Port
}

// l2Capture lee la captura de cada puerto y rechaza el que no existe o es miembro de un canal.
func l2Capture(names []string, outs map[string]string) ([]l2Port, error) {
	var caps []l2Port
	for _, n := range names {
		text, ok := outs[showCfg(n)]
		if !ok {
			return nil, cerr("assist.err.capture_missing", "port", n)
		}
		cur, ok := iosxe.ParseInterfaceConfig(text)
		switch {
		case !ok:
			return nil, refuseSnippet("assist.refused.no_existe_en_el_equipo", "port", n)
		case !strings.EqualFold(iosxe.ShortIf(cur.Name), iosxe.ShortIf(n)):
			return nil, cerr("assist.err.capture_mismatch", "port", n)
		case cur.ChannelGroup:
			return nil, refuseSnippet("assist.refused.es_miembro_de_un_canal", "port", n)
		}
		caps = append(caps, l2Port{name: n, text: text, switchport: outs[showSwitchport(n)], cur: cur, l2: iosxe.ParseL2Port(cur)})
	}
	return caps, nil
}

// l2Routed rechaza un puerto ruteado o de capa 3, donde estas funciones de capa 2 no aplican.
func l2Routed(p l2Port) error {
	if p.cur.Routed || p.cur.L3 {
		return refuseSnippet("assist.refused.es_un_puerto_ruteado_o", "port", p.name)
	}
	return nil
}

// statusMode dice qué hace una plantilla con show interfaces X status.
type statusMode int

const (
	statusNone  statusMode = iota
	statusGuard            // puede dejar el puerto err-disabled: el estado entra a Pre y a la línea base, y se espera que no quede inactive ni err-disabled
)

// errdisabledNote avisa que la reversa no saca un puerto de err-disabled.
var errdisabledNote = note("assist.note.errdisabled")

func l2Pre(mode statusMode) func(Values) ([]string, error) {
	return func(v Values) ([]string, error) {
		names, err := ParseInterfaceList(v.Str("interfaces"))
		if err != nil {
			return nil, err
		}
		var pre []string
		for _, n := range names {
			pre = append(pre, showCfg(n), showSwitchport(n))
			if mode != statusNone {
				pre = append(pre, showStatus(n))
			}
		}
		return pre, nil
	}
}

// l2PortTemplate arma la plantilla de un cambio por puerto a partir de lo que cada una decide: qué líneas lleva cada puerto.
func l2PortTemplate(id, name string, fields []Field, fn Function, mode statusMode, notes []i18n.Text, build func(Values, l2Port) ([]l2Feature, error)) Template {
	fields = append([]Field{{Name: "interfaces", Label: "Puertos", Type: TypeInterfaces, Required: true,
		Help: "Lista separada por comas o rangos como Gi1/0/1-4; solo puertos físicos."}}, fields...)
	pre := l2Pre(mode)
	return Template{ID: id, Tech: "l2", Name: name, Platforms: bothPlatforms, Fields: fields, Fn: fn, Pre: pre,
		Plan: func(device string, v Values, outs map[string]string) (DevicePlan, error) {
			names, err := ParseInterfaceList(v.Str("interfaces"))
			if err != nil {
				return DevicePlan{}, err
			}
			caps, err := l2Capture(names, outs)
			if err != nil {
				return DevicePlan{}, err
			}
			pre, _ := pre(v)
			var scopes []l2Scope
			for _, p := range caps {
				feats, err := build(v, p)
				if err != nil {
					return DevicePlan{}, err
				}
				sc := l2Scope{header: "interface " + p.name, baseCmd: showCfg(p.name), baseText: p.text, post: []string{showCfg(p.name)}, feats: feats}
				if mode != statusNone {
					st := showStatus(p.name)
					text, ok := outs[st]
					if !ok {
						return DevicePlan{}, cerr("assist.err.output_missing", "command", st)
					}
					rows, _ := iosxe.ParseIfStatus(text)
					if len(rows) == 0 {
						return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_de", "command", st, "port", p.name)
					}
					sc.post = append(sc.post, st)
					sc.status, sc.base = st, map[string]string{st: text}
				}
				scopes = append(scopes, sc)
			}
			return assembleL2(device, fn, pre, scopes, notes...)
		}}
}

// ---- CheckDevice común: la reversa es la inversa del apply, contra lo capturado ----

type l2Block struct {
	head  string
	lines []string
}

// l2Blocks parte las líneas en bloques por `interface X`; sin encabezados es un solo bloque global.
func l2Blocks(lines []string) ([]l2Block, error) {
	var out []l2Block
	for i, l := range lines {
		if strings.HasPrefix(strings.ToLower(l), "interface ") {
			out = append(out, l2Block{head: l})
			continue
		}
		if len(out) == 0 {
			if i != 0 {
				return nil, errors.New("líneas sin interfaz")
			}
			out = append(out, l2Block{})
		}
		out[len(out)-1].lines = append(out[len(out)-1].lines, l)
	}
	return out, nil
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

// l2Inverse revisa que la reversa de un plan por puerto (o global) sea la inversa del apply: los mismos puertos en orden inverso y, por cada línea,
// la que la deshace en orden inverso: la línea que el puerto tenía en la línea base (Baseline) o, si no tenía ninguna, su `no` exacto.
// keyOf da la clave de una línea (sin el `no`), o vacío si no es de la función.
func l2Inverse(keyOf func(line string) string, baseCmd func(head string) string) func(DevicePlan) error {
	return l2InverseDef(keyOf, baseCmd, nil)
}

// l2InverseDef es l2Inverse con la línea que deshace una clave que el equipo no tenía cuando no es su `no` (por ejemplo `logging trap informational`,
// el nivel de fábrica, porque `no logging trap` se queda en el running y apaga el syslog). def devuelve "" para las claves con el `no` de siempre.
func l2InverseDef(keyOf func(line string) string, baseCmd func(head string) string, def func(key string) string) func(DevicePlan) error {
	return func(d DevicePlan) error {
		ab, err1 := l2Blocks(d.Apply)
		rb, err2 := l2Blocks(d.Rollback)
		if err1 != nil || err2 != nil || len(ab) != len(rb) || len(ab) == 0 {
			return errors.New("la reversa debe recorrer los mismos puertos que el apply, en orden inverso")
		}
		for i, a := range ab {
			r := rb[len(rb)-1-i]
			if !strings.EqualFold(squash(a.head), squash(r.head)) || len(a.lines) != len(r.lines) {
				return fmt.Errorf("la reversa de %q debe tener una línea por cada línea del apply, en orden inverso", a.head)
			}
			was := map[string]string{}
			for _, l := range capturedLines(d.Baseline[baseCmd(a.head)], a.head != "") {
				if k := keyOf(l); k != "" && was[k] == "" {
					was[k] = squash(l)
				}
			}
			for j, al := range a.lines {
				rl := squash(r.lines[len(r.lines)-1-j])
				k := keyOf(al)
				if k == "" || strings.HasPrefix(strings.ToLower(al), "no ") || keyOf(rl) != k {
					return fmt.Errorf("la reversa de %q debe deshacer esa misma línea", al)
				}
				if w, had := was[k]; had {
					if rl != w {
						return fmt.Errorf("la reversa de %q debe restaurar %q, lo que tenía el equipo", al, w)
					}
				} else if factory := ifNil(def, k); factory != "" {
					if rl != factory {
						return fmt.Errorf("la reversa de %q debe ser %q: el equipo no tenía esa línea", al, factory)
					}
				} else if no := "no " + k; rl != no && rl != "no "+squash(al) {
					return fmt.Errorf("la reversa de %q debe ser %q: el equipo no tenía esa línea", al, no)
				}
			}
		}
		return nil
	}
}

func ifNil(def func(string) string, k string) string {
	if def == nil {
		return ""
	}
	return def(k)
}

// capturedLines son las líneas de la captura de un puerto (iface) o de una salida plana (global).
func capturedLines(text string, iface bool) []string {
	if iface {
		c, _ := iosxe.ParseInterfaceConfig(text)
		return c.Lines
	}
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func ifaceBase(head string) string {
	return showCfg(strings.TrimSpace(strings.TrimPrefix(squash(head), "interface ")))
}

// keyByPrefix devuelve la más larga de las claves que abre la línea (sin su `no`), o vacío.
func keyByPrefix(keys ...string) func(string) string {
	return func(line string) string {
		l := strings.TrimPrefix(strings.ToLower(squash(line)), "no ")
		best := ""
		for _, k := range keys {
			if (l == k || strings.HasPrefix(l, k+" ")) && len(k) > len(best) {
				best = k
			}
		}
		return best
	}
}

func ifaceHeader(f []string) error {
	if len(f) != 2 || !ValidInterface(f[1]) {
		return errors.New("solo un puerto físico (nada de Port-channel, Vlan, rangos ni subinterfaces)")
	}
	return nil
}

func oneOf(s string, opts ...string) bool {
	for _, o := range opts {
		if s == o {
			return true
		}
	}
	return false
}

func intIn(s string, lo, hi int) bool {
	n, err := strconv.Atoi(s)
	return err == nil && ntoa(n) == s && n >= lo && n <= hi
}

// ---- speed-duplex ----

var speedKeys = keyByPrefix("speed", "duplex")

// SnippetSpeedDuplex fija velocidad y duplex de puertos físicos.
var SnippetSpeedDuplex = Function{
	Name:    "snippet-speed-duplex",
	Allowed: []string{"interface", "speed", "duplex", "no speed", "no duplex"},
	Check: func(line string) error {
		f := strings.Fields(strings.ToLower(line))
		switch {
		case f[0] == "interface":
			return ifaceHeader(f)
		case len(f) == 2 && f[0] == "speed" && oneOf(f[1], "auto", "10", "100", "1000"):
		case len(f) == 2 && f[0] == "duplex" && oneOf(f[1], "auto", "full", "half"):
		case len(f) == 2 && f[0] == "no" && oneOf(f[1], "speed", "duplex"):
		default:
			return cerr("assist.err.speed_duplex_form")
		}
		return nil
	},
	CheckDevice: l2Inverse(speedKeys, func(h string) string { return ifaceBase(h) }),
}

func speedDuplexBuild(v Values, p l2Port) ([]l2Feature, error) {
	speed, duplex := v.Str("speed"), v.Str("duplex")
	if speed == "" && duplex == "" {
		return nil, cerr("assist.err.speed_duplex_required")
	}
	if err := l2Routed(p); err != nil {
		return nil, err
	}
	for _, c := range []struct{ what, val string }{{"speed", p.l2.Speed}, {"duplex", p.l2.Duplex}} {
		if c.val != "" && !oneOf(c.val, "auto", "10", "100", "1000", "full", "half") {
			return nil, refuseSnippet("assist.refused.tiene_que_la_reversa_no", "port", p.name, "what", c.what, "val", c.val)
		}
	}
	if effSpeed, effDuplex := ifElse(speed != "", speed, p.l2.Speed), ifElse(duplex != "", duplex, p.l2.Duplex); effSpeed == "1000" && effDuplex == "half" {
		return nil, refuseSnippet("assist.refused.ios_no_admite_duplex_half", "port", p.name)
	}
	var out []l2Feature
	add := func(kw, want, was string) {
		switch {
		case want == "", want == was, want == "auto" && was == "":
			return
		}
		f := l2Feature{apply: kw + " " + want, back: ifElse(was != "", kw+" "+was, "no "+kw), exp: Expect{Line: kw + " " + want, Present: true}}
		if want == "auto" { // IOS no muestra el valor por defecto
			f.exp = Expect{Line: kw, Present: false, Prefix: true}
		}
		out = append(out, f)
	}
	add("speed", speed, p.l2.Speed)
	add("duplex", duplex, p.l2.Duplex)
	return out, nil
}

// ---- storm-control ----

// shutdown y trap son banderas independientes (pueden estar las dos): su clave es la línea completa.
var stormKeys = keyByPrefix("storm-control broadcast level", "storm-control multicast level", "storm-control unicast level", "storm-control action shutdown", "storm-control action trap")

var stormLevelRe = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,2})?)(?: (\d{1,3}(?:\.\d{1,2})?))?$`)

// stormWasRe lee lo capturado de un tipo: «level 30.00» o «level 30.00 10.00».
var stormWasRe = regexp.MustCompile(`^level (\d{1,3}(?:\.\d{1,2})?(?: \d{1,3}(?:\.\d{1,2})?)?)$`)

func stormPct(s string) bool {
	x, err := strconv.ParseFloat(s, 64)
	return err == nil && x >= 0 && x <= 100
}

// SnippetStormControl fija el umbral de tormenta de difusión, multicast y unicast, y la acción.
var SnippetStormControl = Function{
	Name:    "snippet-storm-control",
	Allowed: []string{"interface", "storm-control", "no storm-control"},
	Check: func(line string) error {
		f := strings.Fields(strings.ToLower(line))
		switch {
		case f[0] == "interface":
			return ifaceHeader(f)
		case f[0] == "storm-control" && len(f) >= 4 && f[2] == "level" && oneOf(f[1], "broadcast", "multicast", "unicast"):
			m := stormLevelRe.FindStringSubmatch(strings.Join(f[3:], " "))
			if m == nil || !stormPct(m[1]) || m[2] != "" && !stormPct(m[2]) {
				return cerr("assist.err.storm_threshold")
			}
		case f[0] == "storm-control" && len(f) == 3 && f[1] == "action" && oneOf(f[2], "shutdown", "trap"):
		case len(f) == 4 && f[0] == "no" && f[1] == "storm-control" && f[3] == "level" && oneOf(f[2], "broadcast", "multicast", "unicast"):
		case len(f) == 4 && f[0] == "no" && f[1] == "storm-control" && f[2] == "action" && oneOf(f[3], "shutdown", "trap"):
		default:
			return cerr("assist.err.storm_form")
		}
		return nil
	},
	CheckDevice: l2Inverse(stormKeys, ifaceBase),
}

// decimal2 escribe un decimal validado con dos decimales, como lo muestra IOS.
func decimal2(s string) string {
	i, f, _ := strings.Cut(s, ".")
	n, _ := strconv.Atoi(i)
	return ntoa(n) + "." + (f + "00")[:2]
}

func stormBuild(v Values, p l2Port) ([]l2Feature, error) {
	if !v.Has("broadcast") && !v.Has("multicast") && !v.Has("unicast") && !v.Has("action") {
		return nil, cerr("assist.err.storm_need_threshold")
	}
	if err := l2Routed(p); err != nil {
		return nil, err
	}
	var out []l2Feature
	for _, t := range []string{"broadcast", "multicast", "unicast"} {
		if !v.Has(t) {
			continue
		}
		want, was := decimal2(v.Str(t)), ""
		if raw := p.l2.Storm[t]; raw != "" {
			m := stormWasRe.FindStringSubmatch(raw)
			if m == nil {
				return nil, refuseSnippet("assist.refused.tiene_storm_control_umbral_en", "port", p.name, "t", t, "raw", raw)
			}
			was = m[1]
		}
		if want == was {
			continue
		}
		f := l2Feature{apply: "storm-control " + t + " level " + want, back: ifElse(was != "", "storm-control "+t+" level "+was, "no storm-control "+t+" level")}
		f.exp = Expect{Line: f.apply, Present: true}
		if want == "100.00" { // el nivel de fábrica no sale en el running-config
			f.exp = Expect{Line: "storm-control " + t + " level", Present: false, Prefix: true}
		}
		out = append(out, f)
	}
	for _, was := range p.l2.StormActions {
		if !oneOf(was, "shutdown", "trap") {
			return nil, refuseSnippet("assist.refused.tiene_storm_control_action_y", "port", p.name, "was", was)
		}
	}
	// Cada acción es una bandera: la que ya estaba no se toca, y la que se agrega se quita con su propio no.
	if a := v.Str("action"); a != "" && !slices.Contains(p.l2.StormActions, a) {
		out = append(out, l2Feature{apply: "storm-control action " + a, back: "no storm-control action " + a,
			exp: Expect{Line: "storm-control action " + a, Present: true}})
	}
	return out, nil
}

// ---- portfast-bpduguard ----

var spanKeys = keyByPrefix("spanning-tree portfast", "spanning-tree bpduguard")

// SnippetPortfast activa portfast y BPDU guard en puertos de acceso.
var SnippetPortfast = Function{
	Name:    "snippet-portfast-bpduguard",
	Allowed: []string{"interface", "spanning-tree portfast", "no spanning-tree portfast", "spanning-tree bpduguard", "no spanning-tree bpduguard"},
	Check: func(line string) error {
		f := strings.Fields(strings.ToLower(line))
		switch {
		case f[0] == "interface":
			return ifaceHeader(f)
		case len(f) == 2 && f[0] == "spanning-tree" && f[1] == "portfast":
		case len(f) == 3 && f[0] == "no" && f[1] == "spanning-tree" && f[2] == "portfast":
		case len(f) == 3 && f[0] == "spanning-tree" && f[1] == "bpduguard" && oneOf(f[2], "enable", "disable"):
		case len(f) == 3 && f[0] == "no" && f[1] == "spanning-tree" && f[2] == "bpduguard":
		default:
			return cerr("assist.err.spanning_tree_form")
		}
		return nil
	},
	CheckDevice: l2Inverse(spanKeys, ifaceBase),
}

// l2Access exige un puerto de acceso con switchport mode access (en la captura o como modo administrativo static access); uno dynamic no.
func l2Access(p l2Port) error {
	toAccess, err := accessPort(p.name, p.cur, p.switchport)
	if err != nil {
		return refusalOf(err)
	}
	if toAccess {
		return refuseSnippet("assist.refused.esta_en_modo_dynamic_esta", "port", p.name)
	}
	return nil
}

func portfastBuild(v Values, p l2Port) ([]l2Feature, error) {
	if !v.Bool("portfast") && !v.Bool("bpduguard") {
		return nil, cerr("assist.err.portfast_choose")
	}
	if err := l2Access(p); err != nil {
		return nil, err
	}
	var out []l2Feature
	if v.Bool("portfast") {
		switch {
		case p.l2.HasPortfast && !oneOf(p.l2.Portfast, "", "edge"):
			return nil, refuseSnippet("assist.refused.tiene_spanning_tree_portfast_que", "port", p.name, "portfast", p.l2.Portfast)
		case !p.l2.HasPortfast:
			// IOS puede mostrar la línea como «portfast edge»: la reversa «no spanning-tree portfast» quita las dos formas (regla de #47).
			out = append(out, l2Feature{apply: "spanning-tree portfast", back: "no spanning-tree portfast",
				exp: Expect{Line: "spanning-tree portfast", Present: true, Prefix: true}})
		}
	}
	if v.Bool("bpduguard") {
		switch was := p.l2.Bpduguard; {
		case was != "" && !oneOf(was, "enable", "disable"):
			return nil, refuseSnippet("assist.refused.tiene_spanning_tree_bpduguard_que", "port", p.name, "was", was)
		case was != "enable":
			out = append(out, l2Feature{apply: "spanning-tree bpduguard enable", back: ifElse(was != "", "spanning-tree bpduguard "+was, "no spanning-tree bpduguard"),
				exp: Expect{Line: "spanning-tree bpduguard enable", Present: true}})
		}
	}
	return out, nil
}

// ---- port-security ----

var secKeys = keyByPrefix("switchport port-security", "switchport port-security maximum", "switchport port-security violation", "switchport port-security aging time")

// SnippetPortSecurity activa port-security en un puerto de acceso con máximo, violación y envejecimiento opcionales.
var SnippetPortSecurity = Function{
	Name:    "snippet-port-security",
	Allowed: []string{"interface", "switchport port-security", "no switchport port-security"},
	Check: func(line string) error {
		f := strings.Fields(strings.ToLower(line))
		if f[0] == "interface" {
			return ifaceHeader(f)
		}
		neg := f[0] == "no"
		if neg {
			f = f[1:]
		}
		rest := f[2:] // tras «switchport port-security»
		switch {
		case len(rest) == 0:
		case rest[0] == "maximum" && (neg && len(rest) == 1 || !neg && len(rest) == 2 && intIn(rest[1], 1, 3072)):
		case rest[0] == "violation" && (neg && len(rest) == 1 || !neg && len(rest) == 2 && oneOf(rest[1], "protect", "restrict", "shutdown")):
		case rest[0] == "aging" && len(rest) >= 2 && rest[1] == "time" && (neg && len(rest) == 2 || !neg && len(rest) == 3 && intIn(rest[2], 0, 1440)):
		default:
			return cerr("assist.err.port_security_form")
		}
		return nil
	},
	CheckDevice: l2Inverse(secKeys, ifaceBase),
}

func portSecurityBuild(v Values, p l2Port) ([]l2Feature, error) {
	if err := l2Routed(p); err != nil {
		return nil, err
	}
	switch {
	case p.cur.Trunk:
		return nil, refuseSnippet("assist.refused.es_trunk_port_security_solo", "port", p.name)
	case p.cur.Mode != "access":
		return nil, refuseSnippet("assist.refused.no_esta_en_switchport_mode", "port", p.name)
	case len(p.l2.PortSecurity) > 0:
		return nil, refuseSnippet("assist.refused.ya_tiene_port_security_la", "port", p.name, "config", p.l2.PortSecurity[0])
	}
	var out []l2Feature
	// Los valores de fábrica (1, shutdown, 0) no salen en el running-config.
	add := func(sub, val, def string) {
		if val == "" {
			return
		}
		line := "switchport port-security " + sub + " " + val
		f := l2Feature{apply: line, back: "no switchport port-security " + sub, exp: Expect{Line: line, Present: true}}
		if val == def {
			f.exp = Expect{Line: "switchport port-security " + sub, Present: false, Prefix: true}
		}
		out = append(out, f)
	}
	add("maximum", v.Str("maximum"), "1")
	add("violation", v.Str("violation"), "shutdown")
	add("aging time", v.Str("aging_time"), "0")
	// Se activa al final: no hay ventana con el máximo de fábrica (1). La reversa lo apaga primero y luego quita cada subcomando.
	out = append(out, l2Feature{apply: "switchport port-security", back: "no switchport port-security", exp: Expect{Line: "switchport port-security", Present: true}})
	return out, nil
}

// ---- errdisable-recovery ----

const errdisableCmd = "show running-config | include errdisable recovery"

var errdisableCauses = []string{"bpduguard", "psecure-violation", "storm-control", "link-flap", "udld", "loopback"}

func errCauseField(c string) string { return "cause_" + strings.ReplaceAll(c, "-", "_") }

func errdisableKey(line string) string {
	f := strings.Fields(strings.ToLower(strings.TrimPrefix(squash(line), "no ")))
	switch {
	case len(f) >= 4 && f[0] == "errdisable" && f[1] == "recovery" && f[2] == "cause":
		return strings.Join(f[:4], " ")
	case len(f) >= 3 && f[0] == "errdisable" && f[1] == "recovery" && f[2] == "interval":
		return "errdisable recovery interval"
	}
	return ""
}

// SnippetErrdisable activa la recuperación automática de errdisable por causa y fija su intervalo.
var SnippetErrdisable = Function{
	Name:    "snippet-errdisable-recovery",
	Allowed: []string{"errdisable recovery cause", "errdisable recovery interval", "no errdisable recovery cause", "no errdisable recovery interval"},
	Check: func(line string) error {
		f := strings.Fields(strings.ToLower(line))
		neg := f[0] == "no"
		if neg {
			f = f[1:]
		}
		switch {
		case len(f) == 4 && f[2] == "cause" && oneOf(f[3], errdisableCauses...):
		case f[2] == "interval" && (neg && len(f) == 3 || !neg && len(f) == 4 && intIn(f[3], 30, 86400)):
		default:
			return errors.New("solo errdisable recovery cause (bpduguard, psecure-violation, storm-control, link-flap, udld, loopback), interval 30-86400 y su no")
		}
		return nil
	},
	CheckDevice: l2Inverse(errdisableKey, func(string) string { return errdisableCmd }),
}

func errdisablePlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	text, ok := outs[errdisableCmd]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", errdisableCmd)
	}
	cur, ok := iosxe.ParseErrdisableRecovery(text)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", errdisableCmd, "device", device)
	}
	on := map[string]bool{}
	for _, c := range cur.Causes {
		if c == "all" {
			return DevicePlan{}, refuseSnippet("assist.refused.tiene_errdisable_recovery_cause_all", "device", device)
		}
		on[c] = true
	}
	var feats []l2Feature
	for _, c := range errdisableCauses {
		if v.Bool(errCauseField(c)) && !on[c] {
			line := "errdisable recovery cause " + c
			feats = append(feats, l2Feature{apply: line, back: "no " + line, exp: Expect{Line: line, Present: true}})
		}
	}
	if want := v.Str("interval"); want != "" && want != ifElse(cur.Interval != "", cur.Interval, "300") {
		f := l2Feature{apply: "errdisable recovery interval " + want, exp: Expect{Line: "errdisable recovery interval " + want, Present: true}}
		f.back = ifElse(cur.Interval != "", "errdisable recovery interval "+cur.Interval, "no errdisable recovery interval")
		if want == "300" { // el intervalo de fábrica no sale en el running-config
			f.exp = Expect{Line: "errdisable recovery interval", Present: false, Prefix: true}
		}
		feats = append(feats, f)
	}
	if len(feats) == 0 && !hasErrdisableRequest(v) {
		return DevicePlan{}, cerr("assist.err.errdisable_choose")
	}
	return assembleL2(device, SnippetErrdisable, []string{errdisableCmd},
		[]l2Scope{{baseCmd: errdisableCmd, baseText: text, post: []string{errdisableCmd}, feats: feats}})
}

func hasErrdisableRequest(v Values) bool {
	for _, c := range errdisableCauses {
		if v.Bool(errCauseField(c)) {
			return true
		}
	}
	return v.Has("interval")
}

// ---- modo-puerto ----

// Supuestos sin validar en laboratorio: dynamic auto es el valor de fábrica de un Catalyst de acceso y IOS no lo muestra en el running-config
// (por eso `no switchport mode` lo devuelve a ese estado); access y dynamic desirable salen como «switchport mode ...». Como la línea de
// dynamic auto puede salir o no, su condición se lee del Administrative Mode de show interfaces X switchport, que lo muestra siempre.

var modeKeys = keyByPrefix("switchport mode")

// SnippetPortMode fija el modo de un puerto de acceso: access, dynamic auto, dynamic desirable o el de fábrica. Nunca trunk.
var SnippetPortMode = Function{
	Name:    "snippet-modo-puerto",
	Allowed: []string{"interface", "switchport mode", "no switchport mode"},
	Check: func(line string) error {
		f := strings.Fields(strings.ToLower(line))
		switch {
		case f[0] == "interface":
			return ifaceHeader(f)
		case oneOf(strings.Join(f, " "), "switchport mode access", "switchport mode dynamic auto", "switchport mode dynamic desirable", "no switchport mode"):
		default:
			return errors.New("solo switchport mode access|dynamic auto|dynamic desirable y no switchport mode (nunca trunk)")
		}
		return nil
	},
	CheckDevice: portModeInverse,
}

// portModeInverse: por puerto, una línea de modo en el apply y, en la reversa, la que tenía el puerto en la línea base o `no switchport mode`
// si no tenía. No sirve l2Inverse porque aquí el apply también puede ser `no switchport mode`.
func portModeInverse(d DevicePlan) error {
	ab, err1 := l2Blocks(d.Apply)
	rb, err2 := l2Blocks(d.Rollback)
	if err1 != nil || err2 != nil || len(ab) != len(rb) || len(ab) == 0 {
		return errors.New("la reversa debe recorrer los mismos puertos que el apply, en orden inverso")
	}
	for i, a := range ab {
		r := rb[len(rb)-1-i]
		if !strings.EqualFold(squash(a.head), squash(r.head)) || len(a.lines) != 1 || len(r.lines) != 1 {
			return fmt.Errorf("la reversa de %q debe ser una sola línea de modo, en orden inverso", a.head)
		}
		// Sin la captura del puerto no se sabe qué restaurar: ni «no switchport mode» se acepta a ciegas.
		iface := strings.TrimSpace(strings.TrimPrefix(squash(a.head), "interface "))
		if c, ok := iosxe.ParseInterfaceConfig(d.Baseline[ifaceBase(a.head)]); !ok || !strings.EqualFold(iosxe.ShortIf(c.Name), iosxe.ShortIf(iface)) {
			return fmt.Errorf("falta la línea base legible de %s: sin ella la reversa no sabe qué restaurar", iface)
		}
		want := "no switchport mode"
		for _, l := range capturedLines(d.Baseline[ifaceBase(a.head)], true) {
			if modeKeys(l) != "" {
				want = squash(l)
				break
			}
		}
		if got := squash(r.lines[0]); got != want {
			return fmt.Errorf("la reversa de %q debe ser %q (lo que tenía el equipo), no %q", a.lines[0], want, got)
		}
	}
	return nil
}

func oneOfPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// portModeNow dice en qué modo está el puerto (access, dynamic auto o dynamic desirable) o rechaza el que esta función no debe tocar.
func portModeNow(p l2Port, toDynamic bool) (string, error) {
	if err := l2Routed(p); err != nil {
		return "", err
	}
	if p.cur.Trunk {
		return "", refuseSnippet("assist.refused.tiene_trunk_configurado_esta_funcion", "port", p.name)
	}
	for _, l := range p.cur.Lines {
		low := strings.ToLower(l)
		switch {
		case strings.HasPrefix(low, "switchport private-vlan "):
			return "", refuseSnippet("assist.refused.usa_private_vlan", "port", p.name)
		case toDynamic && oneOfPrefix(low, "switchport nonegotiate", "switchport port-security", "authentication port-control", "dot1x pae"):
			return "", refuseSnippet("assist.refused.tiene_que_ios_no_admite", "port", p.name, "line", l)
		}
	}
	mode := p.cur.Mode
	switch {
	case mode == "":
		// Sin línea de modo solo el de fábrica se restaura con `no switchport mode`; otro modo administrativo no.
		admin, ok := iosxe.ParseSwitchportMode(p.switchport)
		switch {
		case !ok:
			return "", refuseSnippet("assist.refused.no_tiene_linea_de_modo", "port", p.name)
		case admin != "dynamic auto":
			return "", refuseSnippet("assist.refused.esta_en_modo_administrativo_sin", "port", p.name, "admin", admin)
		}
		mode = admin
	case mode != "access" && !isDynamicMode(mode):
		return "", refuseSnippet("assist.refused.esta_en_modo_solo_se", "port", p.name, "mode", mode)
	}
	if mode != "access" {
		// Un dynamic que negoció un trunk (DTP no sale en el running-config) pierde tráfico si se cambia.
		switch oper, ok := iosxe.ParseSwitchportOperMode(p.switchport); {
		case !ok:
			return "", refuseSnippet("assist.refused.esta_en_modo_dynamic_y", "port", p.name)
		case oper == "trunk":
			return "", refuseSnippet("assist.refused.esta_en_modo_dynamic_y2", "port", p.name)
		case oper != "down" && oper != "static access":
			return "", refuseSnippet("assist.refused.esta_en_modo_dynamic_y3", "port", p.name, "oper", oper)
		}
	}
	return mode, nil
}

// showSwitchportMode son solo las líneas de modo de show interfaces X switchport.
func showSwitchportMode(iface string) string { return showSwitchport(iface) + " | include Mode:" }

var portModeNote = note("assist.note.port_mode")

func portModePlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	names, err := ParseInterfaceList(v.Str("interfaces"))
	if err != nil {
		return DevicePlan{}, err
	}
	caps, err := l2Capture(names, outs)
	if err != nil {
		return DevicePlan{}, err
	}
	pre, _ := l2Pre(statusNone)(v)
	want := v.Str("mode")
	target := ifElse(want == "fabrica", "dynamic auto", want)
	notes := []i18n.Text{portModeNote}
	var scopes []l2Scope
	for _, p := range caps {
		now, err := portModeNow(p, want != "access")
		if err != nil {
			return DevicePlan{}, err
		}
		if now == target && (want != "fabrica" || p.cur.Mode == "") {
			notes = append(notes, note("assist.note.port_mode_same", "port", p.name, "mode", now))
			continue
		}
		f := l2Feature{apply: ifElse(want == "fabrica", "no switchport mode", "switchport mode "+want),
			back: ifElse(p.cur.Mode != "", "switchport mode "+p.cur.Mode, "no switchport mode")}
		sc := l2Scope{header: "interface " + p.name, baseCmd: showCfg(p.name), baseText: p.text, post: []string{showCfg(p.name)}}
		switch want {
		case "access":
			f.exp = Expect{Line: f.apply, Present: true}
		default:
			// Post y Expect leen un comando distinto del de la línea base: la línea base lleva el switchport completo (sirve para el drift de
			// antes de aplicar) y, si Post lo leyera también, el motor lo guardaría y bloquearía la reversa en cuanto el Operational Mode
			// cambie solo (el rebote del enlace). Este filtro no entra a la línea base. DTP puede tardar más que la lectura: el trunk
			// negociado se ve a mejor esfuerzo.
			sw := showSwitchportMode(p.name)
			sc.post = append(sc.post, sw)
			sc.expect = append(sc.expect, Expect{Command: sw, Line: "Operational Mode: trunk"})
			if want == "dynamic desirable" {
				f.exp = Expect{Line: f.apply, Present: true}
				break
			}
			// dynamic auto y fábrica: la línea no sale en el running-config; el modo se lee del switchport.
			f.exp = Expect{Command: sw, Line: "Administrative Mode: dynamic auto", Present: true}
			if want == "fabrica" {
				sc.expect = append(sc.expect, Expect{Command: showCfg(p.name), Line: "switchport mode", Prefix: true})
			}
		}
		if now != "access" {
			sc.base = map[string]string{showSwitchport(p.name): p.switchport}
		}
		sc.feats = []l2Feature{f}
		scopes = append(scopes, sc)
	}
	return assembleL2(device, SnippetPortMode, pre, scopes, notes...)
}

func l2PortTemplates() []Template {
	return []Template{
		l2PortTemplate("speed-duplex", "Velocidad y duplex de puertos", []Field{
			{Name: "speed", Label: "Velocidad", Type: TypeChoice, Choices: []string{"auto", "10", "100", "1000"}, Help: "Vacío no la toca. auto la devuelve a negociación."},
			{Name: "duplex", Label: "Duplex", Type: TypeChoice, Choices: []string{"auto", "full", "half"}, Help: "Vacío no lo toca."},
		}, SnippetSpeedDuplex, statusNone,
			// Sin Expect de estado: el post-check corre en cuanto termina el apply y el enlace sigue renegociando.
			[]i18n.Text{note("assist.note.speed_duplex")},
			speedDuplexBuild),
		l2PortTemplate("storm-control", "Storm-control de puertos", []Field{
			{Name: "broadcast", Label: "Umbral de difusión (%)", Type: TypeDecimal, Min: 0, Max: 100, Help: "0.00-100.00; vacío no lo toca."},
			{Name: "multicast", Label: "Umbral de multicast (%)", Type: TypeDecimal, Min: 0, Max: 100},
			{Name: "unicast", Label: "Umbral de unicast (%)", Type: TypeDecimal, Min: 0, Max: 100},
			{Name: "action", Label: "Acción al superarlo", Type: TypeChoice, Choices: []string{"shutdown", "trap"}, Help: "Vacío no la toca. shutdown y trap son independientes: se pueden tener las dos."},
		}, SnippetStormControl, statusGuard, []i18n.Text{errdisabledNote}, stormBuild),
		l2PortTemplate("portfast-bpduguard", "Portfast y BPDU guard en puertos de acceso", []Field{
			{Name: "portfast", Label: "Portfast", Type: TypeBool, Default: "true", Help: "Solo puertos de acceso hacia equipos finales."},
			{Name: "bpduguard", Label: "BPDU guard", Type: TypeBool, Default: "true"},
		}, SnippetPortfast, statusGuard, []i18n.Text{errdisabledNote}, portfastBuild),
		l2PortTemplate("port-security", "Port-security en puertos de acceso", []Field{
			{Name: "maximum", Label: "Máximo de direcciones MAC", Type: TypeInt, Min: 1, Max: 3072, Default: "1"},
			{Name: "violation", Label: "Acción ante violación", Type: TypeChoice, Choices: []string{"protect", "restrict", "shutdown"}, Default: "shutdown"},
			{Name: "aging_time", Label: "Envejecimiento (minutos)", Type: TypeInt, Min: 0, Max: 1440, Help: "0 = no envejece."},
		}, SnippetPortSecurity, statusGuard, []i18n.Text{errdisabledNote}, portSecurityBuild),
		{ID: "errdisable-recovery", Tech: "l2", Name: "Recuperación automática de errdisable", Platforms: bothPlatforms, Fn: SnippetErrdisable,
			Fields: append(func() []Field {
				var fs []Field
				for _, c := range errdisableCauses {
					fs = append(fs, Field{Name: errCauseField(c), Label: "Recuperar por " + c, Type: TypeBool, Default: "false"})
				}
				return fs
			}(), Field{Name: "interval", Label: "Intervalo (segundos)", Type: TypeInt, Min: 30, Max: 86400, Help: "30-86400; vacío no lo toca."}),
			Pre:  func(Values) ([]string, error) { return []string{errdisableCmd}, nil },
			Plan: errdisablePlan},
		{ID: "modo-puerto", Tech: "l2", Name: "Modo del puerto (acceso o dinámico)", Platforms: bothPlatforms, Fn: SnippetPortMode,
			Fields: []Field{
				{Name: "interfaces", Label: "Puertos", Type: TypeInterfaces, Required: true, Help: "Lista separada por comas o rangos como Gi1/0/1-4; solo puertos físicos de acceso."},
				{Name: "mode", Label: "Modo", Type: TypeChoice, Required: true, Choices: []string{"access", "dynamic auto", "dynamic desirable", "fabrica"},
					Help: "fabrica = no switchport mode (el valor de fábrica, dynamic auto en un Catalyst de acceso). Nunca trunk."},
			},
			Pre:  l2Pre(statusNone),
			Plan: portModePlan},
	}
}
