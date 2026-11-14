package playbook

import (
	"net/netip"
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

// splitPipes parte cmd por «|» fuera de comillas dobles; false si quedó una comilla sin cerrar. NX-OS trata cada «|»
// como un pipe nuevo, pero dentro de comillas es parte de la expresión regular («egrep "A|B"»).
func splitPipes(cmd string) ([]string, bool) {
	if strings.Contains(cmd, `""`) || strings.Contains(cmd, `\"`) { // cómo las lee NX-OS (¿comilla escapada?) no está claro: fuera
		return nil, false
	}
	var segs []string
	start, in := 0, false
	for i := 0; i < len(cmd); i++ {
		switch cmd[i] {
		case '"':
			in = !in
		case '|':
			if !in {
				segs, start = append(segs, cmd[start:i]), i+1
			}
		}
	}
	return append(segs, cmd[start:]), !in
}

// checkNXOS aplica las reglas de CheckDenied a un comando de NX-OS (ya validado como ASCII imprimible y sin «;»).
func checkNXOS(cmd string) error {
	if strings.Contains(cmd, ">") { // «> bootflash:f» y «>> f» escriben
		return denied(cmd, "playbook.why.redirect")
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
	tech := len(fields) > 1 && len(fields[1]) >= 4 && strings.HasPrefix("tech-support", fields[1])
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
		f := strings.Fields(seg)
		if len(f) == 0 || !slices.Contains(nxPipeOK, f[0]) {
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
