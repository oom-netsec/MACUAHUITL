package playbook

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Primer comando de lectura de NX-OS (prefijo único, como IOS). «run bash», «guestshell», «python», «source»,
// «tclsh», copy, write, install, feature, configure, clear, debug y «event manager» quedan fuera por no estar aquí.
var nxFirst = []word{{"show", "sh"}, {"dir", "dir"}, {"ping", "pi"}, {"ping6", "ping6"}, {"traceroute", "tr"}, {"traceroute6", "traceroute6"}}

// Primer operador tras «|»: solo filtros y formatos, escritos completos (NX-OS acepta abreviaturas, y una que no
// reconocemos podría ser un sumidero).
var nxPipeOK = []string{"include", "exclude", "begin", "section", "count", "grep", "egrep", "head", "last", "wc", "sort", "uniq", "json", "json-pretty", "xml", "no-more", "end"}

// Tokens que hacen escribir a show tech-support (y a otros show) en NX-OS: «binary <uri>», «tar», «compressed», «gzip».
// shortcut: lista de la doc de show tech-support de NX-OS 9.x/10.x recordada, sin validar en equipo; revisar en la T5.
var nxWriteArgs = []string{"binary", "tar", "compressed", "gzip"}

// Palabras de ping/traceroute de NX-OS que abren un sub-diálogo o cambian el modo: un destino que las abrevie se rechaza.
var nxProbeKeywords = []string{"vrf", "multicast", "mpls", "nve", "ip", "ipv6", "ethernet", "mac", "source", "source-interface"}

// splitPipes parte cmd por «|» fuera de comillas dobles; false si las comillas no son limpias. NX-OS trata cada «|»
// como un pipe nuevo, pero dentro de comillas es parte de la expresión regular («egrep "A|B"»). Una «"» solo abre al
// inicio de una palabra (tras inicio, espacio o «|») y solo cierra si la sigue espacio, «|» o el fin; cualquier otra
// (a media palabra, «""», «\"») se rechaza: cómo las lee NX-OS no está claro y una mal leída esconde un «|».
func splitPipes(cmd string) ([]string, bool) {
	var segs []string
	start, in := 0, false
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case c == '"' && !in:
			if i > 0 && cmd[i-1] != ' ' && cmd[i-1] != '|' {
				return nil, false
			}
			in = true
		case c == '"':
			if i+1 < len(cmd) && cmd[i+1] != ' ' && cmd[i+1] != '|' || cmd[i-1] == '"' || cmd[i-1] == '\\' {
				return nil, false
			}
			in = false
		case c == '\\' && i+1 < len(cmd) && cmd[i+1] == '"':
			return nil, false
		case c == '|' && !in:
			segs, start = append(segs, cmd[start:i]), i+1
		}
	}
	return append(segs, cmd[start:]), !in
}

// pipeTokens parte un segmento de pipe por espacios fuera de comillas (splitPipes ya validó que son limpias).
func pipeTokens(seg string) []string {
	var toks []string
	start, in := -1, false
	for i := 0; i <= len(seg); i++ {
		if i < len(seg) && seg[i] == '"' {
			in = !in
		}
		if i == len(seg) || seg[i] == ' ' && !in {
			if start >= 0 {
				toks, start = append(toks, seg[start:i]), -1
			}
		} else if start < 0 {
			start = i
		}
	}
	return toks
}

// Token con forma de sistema de archivos (bootflash:, volatile:, logflash:, usb1:, slot0:…) o ruta absoluta: un
// argumento de pipe así escribe o lee un archivo. Un prefijo de hasta 4 dígitos hexadecimales (un IPv6, «2001:db8::1»)
// no cuenta.
var nxFSToken = regexp.MustCompile(`^[a-z0-9-]+:`)
var hextet = regexp.MustCompile(`^[0-9a-f]{1,4}:`)

func nxFileLike(tok string) bool {
	t := strings.Trim(tok, `"`)
	return strings.HasPrefix(t, "/") || nxFSToken.MatchString(t) && !hextet.MatchString(t)
}

// Opciones de los filtros de texto: palabras largas y sus formas cortas; «next N» y «prev N» llevan un número.
var nxFilterOpts = []string{"ignore-case", "invert-match", "count", "line-number", "word-exp", "-i", "-v", "-c", "-n", "-w", "-x"}

func isNum(s string) bool {
	_, ok := probeNum(s, 0, 9999)
	return ok
}

// checkNXPipe valida un segmento de pipe: operador completo de la lista blanca y sus argumentos.
func checkNXPipe(seg string) bool {
	t := pipeTokens(seg)
	if len(t) == 0 || !slices.Contains(nxPipeOK, t[0]) {
		return false
	}
	for _, a := range t[1:] {
		if nxFileLike(a) {
			return false
		}
	}
	args := t[1:]
	switch t[0] {
	case "include", "exclude", "begin", "section", "grep", "egrep":
		pat := 0
		for i := 0; i < len(args); i++ {
			switch {
			case slices.Contains(nxFilterOpts, args[i]):
			case (args[i] == "next" || args[i] == "prev") && i+1 < len(args) && isNum(args[i+1]):
				i++
			default:
				pat++ // el patrón: uno solo (con espacios va entre comillas)
			}
		}
		return pat == 1
	case "head":
		return len(args) == 0 || len(args) == 1 && isNum(args[0]) || len(args) == 2 && args[0] == "lines" && isNum(args[1])
	case "last":
		return len(args) == 0 || len(args) == 1 && isNum(args[0])
	}
	return len(args) == 0 // count wc no-more json json-pretty xml end sort uniq
}

// checkNXOS aplica las reglas de CheckDenied a un comando de NX-OS (ya validado como ASCII imprimible y sin «;»).
func checkNXOS(cmd string) error {
	if strings.Contains(cmd, "$") { // NX-OS sustituye variables («cli var»): fuera
		return denied(cmd, "playbook.why.subst")
	}
	segs, ok := splitPipes(strings.ToLower(cmd))
	if !ok {
		return denied(cmd, "playbook.why.quote")
	}
	fields := strings.Fields(segs[0])
	if len(fields) == 0 {
		if len(segs) > 1 {
			return denied(cmd, "playbook.why.empty_pipe")
		}
		return nil
	}
	switch {
	case matchAny(nxFirst, fields[0]):
		if !(word{"show", "sh"}).matches(fields[0]) && !(word{"dir", "dir"}).matches(fields[0]) && !validNXProbe(fields) {
			return denied(cmd, "playbook.why.probe_nxos")
		}
	case (word{"terminal", "ter"}).matches(fields[0]):
		if len(fields) != 3 || !matchAny(allowedTerminal, fields[1]) {
			return denied(cmd, "playbook.why.terminal")
		}
	default:
		return denied(cmd, "playbook.why.not_read")
	}
	tech := len(fields) > 1 && len(fields[1]) >= 3 && strings.HasPrefix("tech-support", fields[1])
	for _, f := range fields[1:] {
		if remotePath(f) {
			return denied(cmd, "playbook.why.remote")
		}
		if f != "" && strings.HasPrefix("to-file", f) { // sin equivalente en NX-OS, pero igual de peligroso si existiera
			return denied(cmd, "playbook.why.to_file")
		}
		if tech && len(f) >= 2 {
			for _, w := range nxWriteArgs {
				if strings.HasPrefix(w, f) {
					return denied(cmd, "playbook.why.write_nxos")
				}
			}
		}
	}
	for _, seg := range segs[1:] { // lista blanca en TODOS los segmentos, con la palabra completa
		if !checkNXPipe(seg) {
			return denied(cmd, "playbook.why.pipe_filter_nxos")
		}
	}
	return nil
}

// validNXProbe acepta `ping|ping6|traceroute|traceroute6 DESTINO [opciones]` con opciones de lista cerrada, en
// palabras completas y sin repetir: ping: vrf V, count 1-10, packet-size 1-1500, timeout 1-10, source IP,
// source-interface IF; traceroute: vrf V, source IP, source-interface IF.
func validNXProbe(f []string) bool {
	ping := strings.HasPrefix(f[0], "pi")
	f = f[1:]
	if len(f) == 0 {
		return false
	}
	// «{ip}» sin sustituir (al cargar el playbook): Expand vuelve a pasar CheckDenied con el valor ya validado.
	if !placeholder.MatchString(f[0]) {
		for _, k := range nxProbeKeywords {
			if strings.HasPrefix(k, f[0]) {
				return false
			}
		}
	}
	if holder := placeholder.FindString(f[0]) == f[0]; !holder && !probeName(f[0]) {
		return false
	} else if holder {
		f = f[1:]
		return nxProbeOpts(f, ping)
	}
	if a, err := netip.ParseAddr(f[0]); err == nil && (a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})) {
		return false
	}
	return nxProbeOpts(f[1:], ping)
}

func nxProbeOpts(f []string, ping bool) bool {
	nums := map[string][2]int{"count": {1, 10}, "packet-size": {1, 1500}, "timeout": {1, 10}}
	seen := map[string]bool{}
	for len(f) > 0 {
		o := f[0]
		_, num := nums[o]
		name := o == "vrf" || o == "source" || o == "source-interface"
		if seen[o] || !(name || (num && ping)) || len(f) < 2 {
			return false
		}
		seen[o] = true
		if name && !probeName(f[1]) {
			return false
		}
		if num {
			if _, ok := probeNum(f[1], nums[o][0], nums[o][1]); !ok {
				return false
			}
		}
		f = f[2:]
	}
	return true
}
