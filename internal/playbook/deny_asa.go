package playbook

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Filtros tras la primera «|» en ASA (abreviables). Lo que sigue es la expresión regular: una segunda «|» es
// alternancia de esa regex, no un pipe nuevo.
var asaPipeOps = []word{{"include", "i"}, {"exclude", "e"}, {"begin", "b"}, {"grep", "g"}}

var (
	asaName = regexp.MustCompile(`^[a-z0-9:][a-z0-9._:-]*$`) // destino: IP literal o nombre DNS simple
	asaIf   = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,47}$`)
	asaPort = regexp.MustCompile(`^[a-z0-9-]{1,16}$`)
)

func isHolder(s string) bool { return placeholder.FindString(s) == s && s != "" }

func asaIfName(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil { // una IP no es un nombre de interfaz: «ping IP palabra» no es IFNAME DESTINO
		return false
	}
	return isHolder(s) || asaIf.MatchString(s)
}

// asaDest: IP literal o nombre simple, sin las direcciones que abren el diálogo o hacen difusión.
func asaDest(s string) bool {
	if isHolder(s) {
		return true
	}
	if !asaName.MatchString(s) {
		return false
	}
	return probeDest(s)
}

// asaLone: destino sin IFNAME delante. Una palabra suelta sin punto («inside», «ipv6») es indistinguible de un nombre
// de interfaz o de una palabra clave: se exige IP, dato o nombre con punto.
func asaLone(s string) bool {
	if _, err := netip.ParseAddr(s); err == nil || isHolder(s) {
		return true
	}
	return strings.Contains(s, ".")
}

func asaIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return isHolder(s) || err == nil
}

func asaPortOK(s string) bool {
	if isHolder(s) {
		return true
	}
	if n, err := strconv.Atoi(s); err == nil { // probeNum topa en 4 dígitos
		return n >= 0 && n <= 65535 && len(s) <= 5
	}
	return asaPort.MatchString(s) && s[0] >= 'a' // nombre de puerto (www, https), no un número raro
}

func asaByte(s string) bool { _, ok := probeNum(s, 0, 255); return ok || isHolder(s) }

// asaOpts valida pares «opción valor» (num: tope [lo,hi]) y banderas sueltas, sin repetir, con palabras completas.
func asaOpts(f []string, nums map[string][2]int, flags ...string) bool {
	seen := map[string]bool{}
	for len(f) > 0 {
		o := f[0]
		if seen[o] {
			return false
		}
		seen[o] = true
		if lim, ok := nums[o]; ok {
			if len(f) < 2 {
				return false
			}
			if _, ok := probeNum(f[1], lim[0], lim[1]); !ok {
				return false
			}
			f = f[2:]
			continue
		}
		if o == "source" && slices.Contains(flags, o) { // traceroute: source IFNAME|IP
			if len(f) < 2 || !(asaIfName(f[1]) || asaIP(f[1])) {
				return false
			}
			f = f[2:]
			continue
		}
		if !slices.Contains(flags, o) {
			return false
		}
		f = f[1:]
	}
	return true
}

// validASAPing: ping [IFNAME] DESTINO [repeat 1-10] [timeout 1-10] [size 28-1500]
// y ping tcp [IFNAME] DESTINO PUERTO [count 1-10] [timeout 1-10].
func validASAPing(f []string) bool {
	f = f[1:]
	tcp := len(f) > 0 && f[0] == "tcp"
	if tcp {
		f = f[1:]
	}
	opts := map[string][2]int{"repeat": {1, 10}, "timeout": {1, 10}, "size": {28, 1500}}
	if tcp {
		opts = map[string][2]int{"count": {1, 10}, "timeout": {1, 10}}
	}
	n := 0
	for n < len(f) && !(opts[f[n]] != [2]int{}) {
		n++
	}
	pos := f[:n]
	if !tcp && len(pos) > 0 && (strings.HasPrefix("tcp", pos[0]) || strings.HasPrefix("interface", pos[0]) || pos[0] == "ipv6") && !isHolder(pos[0]) {
		return false // abreviatura de una palabra clave: abre otra sintaxis
	}
	want := 1
	if tcp {
		want = 2
	}
	if len(pos) != want && len(pos) != want+1 {
		return false
	}
	if len(pos) == want+1 { // con IFNAME
		if !asaIfName(pos[0]) {
			return false
		}
		pos = pos[1:]
	} else if !asaLone(pos[0]) {
		return false
	}
	if !asaDest(pos[0]) || tcp && !asaPortOK(pos[1]) {
		return false
	}
	return asaOpts(f[n:], opts)
}

// validASATrace: traceroute DESTINO [source IFNAME|IP] [numeric] [timeout 1-10] [probe 1-5] [use-icmp].
func validASATrace(f []string) bool {
	if len(f) < 2 || !asaDest(f[1]) || !asaLone(f[1]) {
		return false
	}
	return asaOpts(f[2:], map[string][2]int{"timeout": {1, 10}, "probe": {1, 5}}, "numeric", "use-icmp", "source")
}

// validASATracer: packet-tracer input IFNAME {tcp|udp} SRC SPORT DST DPORT [detailed|xml]
// y packet-tracer input IFNAME icmp SRC TYPE CODE DST [detailed|xml]. Lo demás se rechaza.
func validASATracer(f []string) bool {
	if len(f) < 4 || f[1] != "input" || !asaIfName(f[2]) {
		return false
	}
	var body []string
	switch f[3] {
	case "tcp", "udp":
		if len(f) < 8 {
			return false
		}
		body = f[4:8]
		if !asaIP(body[0]) || !asaPortOK(body[1]) || !asaIP(body[2]) || !asaPortOK(body[3]) {
			return false
		}
		f = f[8:]
	case "icmp":
		if len(f) < 8 {
			return false
		}
		body = f[4:8]
		if !asaIP(body[0]) || !asaByte(body[1]) || !asaByte(body[2]) || !asaIP(body[3]) {
			return false
		}
		f = f[8:]
	default:
		return false
	}
	return len(f) == 0 || len(f) == 1 && (f[0] == "detailed" || f[0] == "xml")
}

// checkASA aplica las reglas de CheckDenied a un comando de Cisco ASA (ya validado como ASCII, sin «;», «>», «`» ni «$(»).
// Lista blanca: el primer comando va completo (show acepta «sh» y «sho»); lo demás se rechaza.
func checkASA(cmd string) error { return checkFamily(cmd, asaHead) }

func asaHead(cmd string, fields []string) error {
	switch first := fields[0]; {
	case (word{"show", "sh"}).matches(first):
		return showNoFile(cmd, fields)
	case first == "dir":
	case first == "ping":
		if !validASAPing(fields) {
			return denied(cmd, "playbook.why.probe_asa")
		}
	case first == "traceroute":
		if !validASATrace(fields) {
			return denied(cmd, "playbook.why.probe_asa")
		}
	case first == "packet-tracer":
		if !validASATracer(fields) {
			return denied(cmd, "playbook.why.tracer_asa")
		}
	case first == "terminal":
		if len(fields) != 3 || fields[1] != "pager" && fields[1] != "width" || !isNum(fields[2]) {
			return denied(cmd, "playbook.why.terminal_asa")
		}
	default:
		return denied(cmd, "playbook.why.not_read")
	}
	return nil
}

// showNoFile: «show tech-support file disk0:x» escribe.
func showNoFile(cmd string, fields []string) error {
	for _, f := range fields[1:] {
		if Abbrev(f, "file") {
			return denied(cmd, "playbook.why.show_file_asa")
		}
	}
	return nil
}

// checkFamily es el esqueleto común de ASA y FTD: valida el primer comando con head y luego rutas remotas y pipe.
func checkFamily(cmd string, head func(cmd string, fields []string) error) error {
	cmdPart, pipe, hasPipe := strings.Cut(strings.ToLower(cmd), "|")
	fields := strings.Fields(cmdPart)
	if len(fields) == 0 {
		if hasPipe {
			return denied(cmd, "playbook.why.empty_pipe")
		}
		return nil
	}
	if err := head(cmd, fields); err != nil {
		return err
	}
	for _, f := range fields[1:] {
		if remotePath(f) {
			return denied(cmd, "playbook.why.remote")
		}
	}
	if !hasPipe {
		return nil
	}
	t := strings.Fields(pipe)
	if len(t) == 0 {
		return denied(cmd, "playbook.why.empty_pipe")
	}
	if !matchAny(asaPipeOps, t[0]) {
		return denied(cmd, "playbook.why.pipe_filter_asa")
	}
	t = t[1:]
	if len(t) > 0 && t[0] == "-v" && (word{"grep", "g"}).matches(strings.Fields(pipe)[0]) {
		t = t[1:]
	}
	if len(t) == 0 {
		return denied(cmd, "playbook.why.pipe_filter_asa")
	}
	sink := func(tok string) bool {
		return Abbrev(tok, "redirect") || Abbrev(tok, "tee") || Abbrev(tok, "append")
	}
	if sink(t[0]) && len(t) > 1 { // «a prueba de fallas»: la regex no abre con un sumidero seguido de un destino; «| i redirect» solo sí
		return denied(cmd, "playbook.why.pipe_sink")
	}
	// Algunas versiones de ASA aceptan «| redirect» o «| append» tras el filtro: tras cada «|» posterior tampoco va un
	// sumidero, y ningún token de la parte del pipe puede ser una ruta del equipo o remota (tapar de más está bien).
	for i, seg := range strings.Split(pipe, "|") {
		f := strings.Fields(seg)
		if i > 0 && len(f) > 0 && sink(f[0]) {
			return denied(cmd, "playbook.why.pipe_sink")
		}
		if i > 0 && len(f) > 0 && shellToken(f[0]) { // como en IOS: sscp, email, vsh, bash, python… tras un segundo «|»
			return denied(cmd, "playbook.why.pipe_shell")
		}
		for _, tok := range f {
			if remotePath(tok) {
				return denied(cmd, "playbook.why.remote")
			}
			if asaDevicePath.MatchString(tok) {
				return denied(cmd, "playbook.why.local_path")
			}
		}
	}
	return nil
}

// asaDevicePath: un sistema de archivos local de ASA al inicio del token (disk0:, flash:, system:…).
var asaDevicePath = regexp.MustCompile(`^(?:disk\d+|flash|bootflash|system|nvram|tmp|cache|coredumpfsys):`)
