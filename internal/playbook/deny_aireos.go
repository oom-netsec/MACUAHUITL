package playbook

import (
	"net/netip"
	"regexp"
	"strings"
)

// aireGrep: grep include|exclude "PATRÓN" "COMANDO", sin comillas anidadas ni nada después.
var aireGrep = regexp.MustCompile(`^grep (include|exclude) "([^"]*)" "([^"]*)"$`)

// checkAireOS: CLI de Cisco AireOS 8.x (prompt «(Nombre) >»). Lista blanca: «show …» completo, «ping IP» acotado y
// «grep include|exclude "patrón" "show …"». No hay pipe; todo lo demás (config, debug, save, reset, transfer…) se rechaza.
func checkAireOS(cmd string) error {
	low := strings.ToLower(strings.TrimSpace(cmd))
	if strings.ContainsAny(low, "|?") {
		return denied(cmd, "playbook.why.pipe_aireos")
	}
	if strings.HasPrefix(low, "grep") {
		m := aireGrep.FindStringSubmatch(low)
		if m == nil {
			return denied(cmd, "playbook.why.grep_aireos")
		}
		inner := strings.Fields(m[3])
		// El comando citado pasa por el mismo CheckDenied completo y solo puede ser un show.
		if len(inner) == 0 || inner[0] != "show" || strings.TrimSpace(m[3]) != m[3] {
			return denied(cmd, "playbook.why.grep_aireos")
		}
		if err := checkAireOS(m[3]); err != nil {
			return denied(cmd, "playbook.why.grep_aireos")
		}
		return nil
	}
	if strings.Contains(low, `"`) {
		return denied(cmd, "playbook.why.grep_aireos")
	}
	f := strings.Fields(low)
	if len(f) == 0 {
		return denied(cmd, "playbook.why.not_read")
	}
	for _, a := range f[1:] {
		if remotePath(a) {
			return denied(cmd, "playbook.why.remote")
		}
	}
	// Una «y»/«n» suelta al final contestaría una pregunta de confirmación.
	if last := f[len(f)-1]; len(f) > 1 && (last == "y" || last == "n") {
		return denied(cmd, "playbook.why.confirm_aireos")
	}
	switch f[0] {
	case "show":
		// show run-config (y cualquier abreviatura de 2+ letras) pregunta «Are you sure… (y/N)».
		if len(f) > 1 && len(f[1]) >= 2 && strings.HasPrefix("run-config", f[1]) {
			return denied(cmd, "playbook.why.confirm_aireos")
		}
	case "ping":
		if !validAireOSPing(f) {
			return denied(cmd, "playbook.why.probe_aireos")
		}
	default:
		return denied(cmd, "playbook.why.not_read")
	}
	return nil
}

// validAireOSPing: ping IP [count 1-10] [size 1-1500], sin repetir.
func validAireOSPing(f []string) bool {
	if len(f) < 2 || !asaIP(f[1]) {
		return false
	}
	if a, err := netip.ParseAddr(f[1]); err == nil && badProbeAddr(a) {
		return false
	}
	return asaOpts(f[2:], map[string][2]int{"count": {1, 10}, "size": {1, 1500}})
}
