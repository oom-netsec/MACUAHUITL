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

// Sumideros de pipe: escriben a flash, a la red o abren un shell/pager. En los segmentos tras el primero se rechaza
// todo lo que abrevie uno de ellos, salvo un operador permitido escrito completo.
// shortcut: a prueba de fallas, una alternancia de regex como «include a|email» (o «include a|b», pues «b» abrevia
// bash) se rechaza; se escribe el filtro sin «|» o en dos playbooks.
var nxSinks = []string{"redirect", "tee", "append", "email", "bash", "python", "vsh", "less", "diff"}

// checkNXOS aplica las reglas de CheckDenied a un comando de NX-OS (ya validado como ASCII imprimible).
func checkNXOS(cmd string) error {
	if strings.Contains(cmd, ">") { // «> bootflash:f» y «>> f» escriben
		return denied(cmd, "playbook.why.redirect")
	}
	segs := strings.Split(strings.ToLower(cmd), "|")
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
			return denied(cmd, "playbook.why.probe")
		}
	case (word{"terminal", "ter"}).matches(fields[0]):
		if len(fields) != 3 || !matchAny(allowedTerminal, fields[1]) {
			return denied(cmd, "playbook.why.terminal")
		}
	default:
		return denied(cmd, "playbook.why.not_read")
	}
	for _, f := range fields[1:] {
		if remotePath(f) {
			return denied(cmd, "playbook.why.remote")
		}
	}
	for i, seg := range segs[1:] {
		f := strings.Fields(seg)
		if len(f) == 0 {
			if i == 0 {
				return denied(cmd, "playbook.why.empty_pipe")
			}
			continue // parte de una expresión regular
		}
		if i == 0 {
			if !slices.Contains(nxPipeOK, f[0]) {
				return denied(cmd, "playbook.why.pipe_filter")
			}
			continue
		}
		if slices.Contains(nxPipeOK, f[0]) {
			continue
		}
		for _, s := range nxSinks {
			if Abbrev(f[0], s) {
				return denied(cmd, "playbook.why.pipe_sink")
			}
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
	if len(f) == 0 || !probeName(f[0]) {
		return false
	}
	if a, err := netip.ParseAddr(f[0]); err == nil && (a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})) {
		return false
	}
	f = f[1:]
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
