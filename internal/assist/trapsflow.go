package assist

import (
	"slices"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Plantillas snmp-trap-host y netflow-export. Sin validar en laboratorio: la sintaxis sale de la documentación de Cisco (IOS 15.2E e IOS XE).

const (
	snmpAllCmd = "show running-config | include ^snmp-server"
	flowCmd    = "show running-config | section ^flow"

	flowRec, flowExp, flowMon = "MX-REC", "MX-EXP", "MX-MON"
)

func portOK(s string) bool { return intIn(s, 1, 65535) }

// ---- snmp-trap-host ----

// trapSnmpNames son los traps de la familia snmp que la plantilla activa, en el orden en que se escriben.
var trapSnmpNames = []string{"linkdown", "linkup", "coldstart"}

// parseTrapHostLine lee `snmp-server host A version 2c C udp-port P` (con o sin `no`) y devuelve la IP, el puerto y la community.
func parseTrapHostLine(line string) (addr, port, comm string, neg bool, err error) {
	f := strings.Fields(line)
	if neg = len(f) > 0 && f[0] == "no"; neg {
		f = f[1:]
	}
	if len(f) != 8 || f[0] != "snmp-server" || f[1] != "host" || f[3] != "version" || f[4] != "2c" || f[6] != "udp-port" || !portOK(f[7]) || checkCommunity(f[5]) != nil {
		return "", "", "", neg, lerr("solo snmp-server host A version 2c COMMUNITY udp-port P (P de 1 a 65535) y su no", "only snmp-server host A version 2c COMMUNITY udp-port P (P from 1 to 65535) and its no")
	}
	if err := unicastIPv4("assist.what.snmp_trap_host", f[2]); err != nil {
		return "", "", "", neg, err
	}
	return f[2], f[7], f[5], neg, nil
}

// parseTrapsLine lee `snmp-server enable traps snmp A [B [C]]` (en el orden de trapSnmpNames) o `... traps config`, con o sin `no`.
func parseTrapsLine(line string) (family string, args []string, neg bool, ok bool) {
	f := strings.Fields(line)
	if neg = len(f) > 0 && f[0] == "no"; neg {
		f = f[1:]
	}
	if len(f) < 4 || f[0] != "snmp-server" || f[1] != "enable" || f[2] != "traps" {
		return "", nil, neg, false
	}
	switch {
	case f[3] == "config" && len(f) == 4:
		return "config", nil, neg, true
	case f[3] == "snmp" && len(f) > 4 && len(f) <= 7:
		last := -1
		for _, a := range f[4:] {
			i := slices.Index(trapSnmpNames, a)
			if i <= last { // desconocido, repetido o fuera de orden
				return "", nil, neg, false
			}
			last = i
		}
		return "snmp", f[4:], neg, true
	}
	return "", nil, neg, false
}

// SnippetTrapHost agrega un destino de traps SNMP v2c y los traps snmp y config que el equipo no tuviera. `no snmp-server community` solo está
// para la reversa: IOS crea en silencio, como RO, la community que el host nombra y no existía.
var SnippetTrapHost = Function{
	Name:    "snippet-snmp-trap-host",
	Allowed: []string{"snmp-server host", "snmp-server enable traps", "snmp-server community"},
	AllowNo: true,
	Scrub:   true,
	Check: func(line string) error {
		f := strings.Fields(line)
		switch {
		case len(f) > 1 && f[0] == "no" && f[1] == "snmp-server" && len(f) > 2 && f[2] == "community" || f[0] == "snmp-server" && f[1] == "community":
			if len(f) == 4 && f[0] == "no" && checkCommunity(f[3]) == nil {
				return nil
			}
			return lerr("de la community solo se admite `no snmp-server community C` (la reversa de la que creó el host)", "only `no snmp-server community C` is allowed for the community (the rollback of the one the host created)")
		case strings.Contains(line, " host "):
			_, _, _, _, err := parseTrapHostLine(line)
			return err
		}
		if _, _, _, ok := parseTrapsLine(line); !ok {
			return lerr("solo snmp-server enable traps snmp linkdown linkup coldstart (o parte, en ese orden) y snmp-server enable traps config", "only snmp-server enable traps snmp linkdown linkup coldstart (or part of it, in that order) and snmp-server enable traps config")
		}
		return nil
	},
	// La reversa quita exactamente lo que el apply puso: el host, los traps que no estaban y, si no existía, la community que IOS creó.
	CheckDevice: func(d DevicePlan) error {
		text, has := d.Baseline[snmpAllCmd]
		hosts, ok1 := iosxe.ParseSNMPHosts(text)
		traps, ok2 := iosxe.ParseSNMPTraps(text)
		comms, ok3 := iosxe.ParseSNMPCommunities(text)
		if !has || !ok1 || !ok2 || !ok3 {
			return lerr("falta la línea base de snmp-server, o no se pudo leer", "the snmp-server baseline is missing, or could not be read")
		}
		if len(d.Apply) == 0 {
			return lerr("el apply empieza con el snmp-server host", "the apply starts with the snmp-server host")
		}
		addr, _, comm, neg, err := parseTrapHostLine(d.Apply[0])
		if err != nil || neg {
			return lerr("el primer apply es el snmp-server host, nunca un no", "the first apply is the snmp-server host, never a no")
		}
		if slices.ContainsFunc(hosts, func(h iosxe.SNMPHost) bool { return h.Addr == addr }) {
			return lerr("el equipo ya tiene un snmp-server host a esa IP: la reversa no lo restauraría", "the device already has an snmp-server host to that IP: the rollback would not restore it")
		}
		back := []string{"no " + squash(d.Apply[0])}
		seenSnmp, seenCfg := false, false
		for _, l := range d.Apply[1:] {
			fam, args, neg, ok := parseTrapsLine(l)
			switch {
			case !ok || neg:
				return lerr("tras el host solo van los traps (snmp y config), sin no", "after the host only the traps (snmp and config) go, without no")
			case fam == "snmp" && !seenSnmp && !seenCfg:
				seenSnmp = true
				if slices.ContainsFunc(args, traps.HasSnmp) {
					return lerr("un trap de snmp ya estaba activo: la reversa lo apagaría", "an snmp trap was already enabled: the rollback would turn it off")
				}
			case fam == "config" && !seenCfg:
				seenCfg = true
				if traps.HasConfig() {
					return lerr("el trap config ya estaba activo: la reversa lo apagaría", "the config trap was already enabled: the rollback would turn it off")
				}
			default:
				return lerr("los traps van una vez cada uno: snmp y luego config", "each trap goes once: snmp and then config")
			}
			back = append(back, "no "+squash(l))
		}
		slices.Reverse(back)
		if !slices.ContainsFunc(comms, func(c iosxe.SNMPCommunity) bool { return c.Name == comm }) {
			back = append(back, "no snmp-server community "+comm)
		}
		if len(d.Rollback) != len(back) {
			return lerr("la reversa son %d líneas: los traps agregados, el host y, si no existía, la community", "the rollback is %d lines: the traps added, the host and, if it did not exist, the community", len(back))
		}
		for i, w := range back {
			if squash(d.Rollback[i]) != w {
				return lerr("la reversa de la línea %d no es la inversa exacta de lo agregado", "rollback line %d is not the exact inverse of what was added", i+1)
			}
		}
		return nil
	},
}

func trapHostValues(v Values) (addr string, port int, comm string) {
	port = v.Int("port")
	if port == 0 {
		port = 162
	}
	return v.Str("address"), port, v.Str("community")
}

func trapsChoice(v Values) (snmp, cfg bool, err error) {
	switch v.Str("traps") {
	case "", "snmp+config":
		return true, true, nil
	case "snmp":
		return true, false, nil
	case "config":
		return false, true, nil
	}
	return false, false, lerr("traps: snmp, config o snmp+config", "traps: snmp, config or snmp+config")
}

func trapHostPre(v Values) ([]string, error) {
	if err := unicastIPv4("assist.what.snmp_trap_host", v.Str("address")); err != nil {
		return nil, err
	}
	if p := v.Int("port"); p < 0 || p > 65535 || v.Has("port") && p == 0 {
		return nil, lerr("el puerto va de 1 a 65535", "the port goes from 1 to 65535")
	}
	if err := checkCommunity(v.Str("community")); err != nil {
		return nil, err
	}
	if _, _, err := trapsChoice(v); err != nil {
		return nil, err
	}
	return []string{snmpAllCmd}, nil
}

func trapHostPlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	pre, err := trapHostPre(v)
	if err != nil {
		return DevicePlan{}, err
	}
	text, ok := outs[snmpAllCmd]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", snmpAllCmd)
	}
	hosts, ok1 := iosxe.ParseSNMPHosts(text)
	traps, ok2 := iosxe.ParseSNMPTraps(text)
	comms, ok3 := iosxe.ParseSNMPCommunities(text)
	if !ok1 || !ok2 || !ok3 {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", snmpAllCmd, "device", device)
	}
	addr, port, comm := trapHostValues(v)
	if slices.ContainsFunc(hosts, func(h iosxe.SNMPHost) bool { return h.Addr == addr }) { // jamás se cita la community
		return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_un_snmp_server_host", "device", device, "addr", addr)
	}
	wantSnmp, wantCfg, _ := trapsChoice(v)
	hostLine := "snmp-server host " + addr + " version 2c " + comm + " udp-port " + strconv.Itoa(port)
	feats := []l2Feature{{apply: hostLine, back: "no " + hostLine, exp: Expect{Column: "snmp-host", Line: addr + " " + strconv.Itoa(port), Present: true}}}
	if missing := slices.DeleteFunc(slices.Clone(trapSnmpNames), traps.HasSnmp); wantSnmp && len(missing) > 0 {
		line := "snmp-server enable traps snmp " + strings.Join(missing, " ")
		feats = append(feats, l2Feature{apply: line, back: "no " + line, exp: Expect{Column: "snmp-traps", Line: "snmp " + strings.Join(missing, " "), Present: true}})
	}
	if wantCfg && !traps.HasConfig() {
		line := "snmp-server enable traps config"
		feats = append(feats, l2Feature{apply: line, back: "no " + line, exp: Expect{Column: "snmp-traps", Line: "config", Present: true}})
	}
	var rb []string
	for i := len(feats) - 1; i >= 0; i-- {
		rb = append(rb, feats[i].back)
	}
	var notes []i18n.Text
	if !slices.ContainsFunc(comms, func(c iosxe.SNMPCommunity) bool { return c.Name == comm }) {
		rb = append(rb, "no snmp-server community "+comm) // IOS la creó sola, como RO, al nombrarla en el host
		notes = append(notes, note("assist.note.snmp_trap_community_new"))
	}
	return assembleG(device, SnippetTrapHost, pre, []l2Scope{{baseCmd: snmpAllCmd, baseText: text, post: []string{snmpAllCmd}, feats: feats, rollback: rb}}, notes, []string{comm})
}

// ---- netflow-export ----

func flowApply(addr string, port int, iface, source string) []string {
	out := []string{"flow record " + flowRec,
		"match ipv4 protocol", "match ipv4 source address", "match ipv4 destination address",
		"match transport source-port", "match transport destination-port",
		// `long` (contadores de 64 bits): es la forma de la documentación de IOS XE y de la serie 3560-X; el 3560-CX queda por confirmar en laboratorio.
		"collect counter bytes long", "collect counter packets long",
		"flow exporter " + flowExp, "destination " + addr, "transport udp " + strconv.Itoa(port), "export-protocol netflow-v9"}
	if source != "" {
		out = append(out, "source "+source)
	}
	return append(out, "flow monitor "+flowMon, "record "+flowRec, "exporter "+flowExp, "cache timeout active 60",
		"interface "+iface, "ip flow monitor "+flowMon+" input")
}

func flowBack(iface string) []string {
	return []string{"interface " + iface, "no ip flow monitor " + flowMon + " input", "no flow monitor " + flowMon, "no flow exporter " + flowExp, "no flow record " + flowRec}
}

var flowFixed = []string{
	"flow record " + flowRec, "match ipv4 protocol", "match ipv4 source address", "match ipv4 destination address", "match transport source-port",
	"match transport destination-port", "collect counter bytes long", "collect counter packets long", "flow exporter " + flowExp, "export-protocol netflow-v9",
	"flow monitor " + flowMon, "record " + flowRec, "exporter " + flowExp, "cache timeout active 60", "ip flow monitor " + flowMon + " input",
}

// SnippetNetflow crea un record, un exporter (NetFlow v9) y un monitor propios (MX-*) y los pone en la entrada de un puerto físico.
var SnippetNetflow = Function{
	Name: "snippet-netflow-export",
	Allowed: []string{"flow record", "flow exporter", "flow monitor", "match", "collect", "destination", "transport", "export-protocol", "source", "record",
		"exporter", "cache", "ip flow monitor", "interface"},
	AllowNo: true,
	Check: func(line string) error {
		bad := lerr("solo las líneas del record, exporter y monitor MX-* de Flexible NetFlow, su ip flow monitor MX-MON input y sus no", "only the lines of the MX-* Flexible NetFlow record, exporter and monitor, its ip flow monitor MX-MON input and their no")
		l := squash(line)
		if _, neg := strings.CutPrefix(l, "no "); neg {
			if slices.Contains(flowBack("X")[1:], l) {
				return nil
			}
			return bad
		}
		f := strings.Fields(l)
		switch {
		case slices.Contains(flowFixed, l):
		case f[0] == "interface" && len(f) == 2 && ValidInterface(f[1]):
		case f[0] == "destination" && len(f) == 2:
			return unicastIPv4("assist.what.netflow_collector", f[1])
		case f[0] == "transport" && len(f) == 3 && f[1] == "udp" && portOK(f[2]):
		case f[0] == "source" && len(f) == 2 && ifaceNameRe.MatchString(f[1]):
		default:
			return bad
		}
		return nil
	},
	CheckDevice: func(d DevicePlan) error {
		var addr, iface, source string
		port := 0
		for _, l := range d.Apply {
			f := strings.Fields(l)
			switch {
			case f[0] == "destination" && len(f) == 2:
				addr = f[1]
			case f[0] == "transport" && len(f) == 3:
				port, _ = strconv.Atoi(f[2])
			case f[0] == "source":
				source = f[1]
			case f[0] == "interface":
				iface = f[1]
			}
		}
		if want := flowApply(addr, port, iface, source); !slices.EqualFunc(d.Apply, want, func(a, b string) bool { return squash(a) == b }) {
			return lerr("el apply debe ser el record, el exporter y el monitor en ese orden y el monitor en la interfaz", "the apply must be the record, the exporter and the monitor in that order and the monitor on the interface")
		}
		if want := flowBack(iface); !slices.EqualFunc(d.Rollback, want, func(a, b string) bool { return squash(a) == b }) {
			return lerr("la reversa debe ser, en orden inverso: el monitor de la interfaz, el monitor, el exporter y el record", "the rollback must be, in reverse order: the interface monitor, the monitor, the exporter and the record")
		}
		objs, ok1 := iosxe.ParseFlowObjects(d.Baseline[flowCmd])
		cur, ok2 := iosxe.ParseInterfaceConfig(d.Baseline[showCfg(iface)])
		if _, has := d.Baseline[flowCmd]; !has || !ok1 || !ok2 {
			return lerr("falta la línea base de flow y de la interfaz, o no se pudo leer", "the flow and interface baseline is missing, or could not be read")
		}
		if slices.Contains(objs.Records, flowRec) || slices.Contains(objs.Exporters, flowExp) || slices.Contains(objs.Monitors, flowMon) || hasInputMonitor(cur) {
			return lerr("el equipo ya tiene alguno de esos objetos o un monitor de entrada en la interfaz: la reversa no lo restauraría", "the device already has one of those objects or an input monitor on the interface: the rollback would not restore it")
		}
		return nil
	},
}

func hasInputMonitor(c iosxe.InterfaceConfig) bool {
	return slices.ContainsFunc(c.Lines, func(l string) bool {
		f := strings.Fields(l)
		return len(f) >= 5 && f[0] == "ip" && f[1] == "flow" && f[2] == "monitor" && f[len(f)-1] == "input"
	})
}

func netflowValues(v Values) (addr string, port int, iface, source string) {
	port = v.Int("port")
	if port == 0 {
		port = 2055
	}
	return v.Str("address"), port, v.Str("interface"), v.Str("source")
}

func netflowPre(v Values) ([]string, error) {
	addr, _, iface, source := netflowValues(v)
	if err := unicastIPv4("assist.what.netflow_collector", addr); err != nil {
		return nil, err
	}
	if p := v.Int("port"); p < 0 || p > 65535 || v.Has("port") && p == 0 {
		return nil, lerr("el puerto va de 1 a 65535", "the port goes from 1 to 65535")
	}
	if !ValidInterface(iface) { // Vlan, Port-channel, Loopback, Tunnel y subinterfaces no
		return nil, cerr("assist.err.not_physical_port", "port", iface)
	}
	pre := []string{flowCmd, showCfg(iface)}
	if source != "" {
		if !ifaceNameRe.MatchString(source) {
			return nil, lerr("interfaz de origen inválida %q", "invalid source interface %q", source)
		}
		pre = append(pre, showCfg(source))
	}
	return pre, nil
}

func netflowPlan(device string, v Values, outs map[string]string) (DevicePlan, error) {
	pre, err := netflowPre(v)
	if err != nil {
		return DevicePlan{}, err
	}
	addr, port, iface, source := netflowValues(v)
	flowText, ok := outs[flowCmd]
	if !ok {
		return DevicePlan{}, cerr("assist.err.output_missing", "command", flowCmd)
	}
	ifText, ok := outs[showCfg(iface)]
	if !ok {
		return DevicePlan{}, cerr("assist.err.capture_missing", "port", iface)
	}
	objs, ok := iosxe.ParseFlowObjects(flowText)
	if !ok {
		return DevicePlan{}, refuseSnippet("assist.refused.no_se_pudo_leer_en", "command", flowCmd, "device", device)
	}
	for _, o := range []struct {
		have []string
		name string
		kind string
	}{{objs.Records, flowRec, "flow record "}, {objs.Exporters, flowExp, "flow exporter "}, {objs.Monitors, flowMon, "flow monitor "}} {
		if slices.Contains(o.have, o.name) {
			return DevicePlan{}, refuseSnippet("assist.refused.ya_tiene_objetos_flow", "device", device, "name", o.kind+o.name)
		}
	}
	cur, ok := iosxe.ParseInterfaceConfig(ifText)
	switch {
	case !ok:
		return DevicePlan{}, refuseSnippet("assist.refused.no_existe_en_el_equipo", "port", iface)
	case !ifaceEq(cur.Name, iface):
		return DevicePlan{}, cerr("assist.err.capture_mismatch", "port", iface)
	case cur.ChannelGroup:
		return DevicePlan{}, refuseSnippet("assist.refused.es_miembro_de_un_canal", "port", iface)
	case hasInputMonitor(cur):
		return DevicePlan{}, refuseSnippet("assist.refused.la_interfaz_ya_tiene_un_monitor", "port", iface, "device", device)
	}
	if source != "" {
		if _, ok := iosxe.ParseInterfaceConfig(outs[showCfg(source)]); !ok {
			return DevicePlan{}, refuseSnippet("assist.refused.la_interfaz_source_no_existe", "port", source, "device", device)
		}
	}
	feats := make([]l2Feature, 0, 24)
	for _, l := range flowApply(addr, port, iface, source) {
		feats = append(feats, l2Feature{apply: l})
	}
	sep := expectSep
	pn := strconv.Itoa(port)
	exp := []Expect{
		{Command: flowCmd, Line: "flow record " + flowRec + sep + "collect counter packets long", Present: true, Column: "section-line"},
		{Command: flowCmd, Line: "flow exporter " + flowExp + sep + "destination " + addr, Present: true, Column: "section-line"},
		{Command: flowCmd, Line: "flow exporter " + flowExp + sep + "transport udp " + pn, Present: true, Column: "section-line"},
		{Command: flowCmd, Line: "flow monitor " + flowMon + sep + "exporter " + flowExp, Present: true, Column: "section-line"},
		{Command: showCfg(iface), Line: "ip flow monitor " + flowMon + " input", Present: true},
	}
	return assembleG(device, SnippetNetflow, pre, []l2Scope{{
		baseCmd: flowCmd, baseText: flowText, post: []string{flowCmd, showCfg(iface)}, base: map[string]string{showCfg(iface): ifText},
		feats: feats, expect: exp, rollback: flowBack(iface),
	}}, []i18n.Text{note("assist.note.netflow_input_only")}, nil)
}

func trapsFlowTemplates() []Template {
	return []Template{
		{ID: "snmp-trap-host", Tech: "gestion", Name: "Destino de traps SNMP", Platforms: bothPlatforms, Fn: SnippetTrapHost,
			Fields: []Field{
				{Name: "address", Label: "Servidor de traps", Type: TypeIPv4, Required: true},
				{Name: "port", Label: "Puerto UDP", Type: TypeInt, Min: 1, Max: 65535, Default: "162", Help: "1-65535; por omisión 162."},
				{Name: "community", Label: "Community", Type: TypeSecret, Required: true, Min: 4, Max: 32, Help: "4-32 caracteres, sin espacios ni @. No se muestra en ninguna parte. Si no existe en el equipo, IOS la crea de solo lectura y la reversa la quita."},
				{Name: "traps", Label: "Traps", Type: TypeChoice, Choices: []string{"snmp", "config", "snmp+config"}, Default: "snmp+config", Help: "snmp = linkdown, linkup y coldstart; config = cambios de configuración. Solo se agregan (y se quitan) los que el equipo no tenía."},
			},
			Pre: trapHostPre, Plan: trapHostPlan},
		{ID: "netflow-export", Tech: "gestion", Name: "Exportar NetFlow (Flexible NetFlow v9)", Platforms: bothPlatforms, Fn: SnippetNetflow,
			Fields: []Field{
				{Name: "address", Label: "Colector", Type: TypeIPv4, Required: true},
				{Name: "port", Label: "Puerto UDP", Type: TypeInt, Min: 1, Max: 65535, Default: "2055", Help: "1-65535; por omisión 2055."},
				{Name: "interface", Label: "Interfaz", Type: TypeText, Required: true, Max: 40, Help: "Puerto físico donde se monitorea el tráfico de entrada; no Vlan, Port-channel, Loopback ni Tunnel."},
				{Name: "source", Label: "Interfaz de origen", Type: TypeText, Max: 40, Pattern: ifaceNameRe.String(), Help: "Opcional, por ejemplo Vlan1: la IP desde la que el equipo exporta."},
			},
			Pre: netflowPre, Plan: netflowPlan},
	}
}
