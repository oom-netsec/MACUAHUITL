package playbook

import "slices"

// checkFTD: CLI normal de Cisco Secure Firewall Threat Defense (prompt «> »). Sin abreviaturas: el primer comando va
// completo. Reusa de ASA los filtros de pipe, las rutas remotas y las formas acotadas de ping, traceroute y
// packet-tracer. Quedan fuera expert, system (diagnostic-cli incluido), capture-traffic y todo lo que no sea lectura.
func checkFTD(cmd string) error { return checkFamily(cmd, ftdHead) }

func ftdHead(cmd string, fields []string) error {
	switch fields[0] {
	case "show":
		return showNoFile(cmd, fields)
	case "ping", "traceroute":
		// «system» (ping system DESTINO, source system…) sale por la interfaz de gestión y su sintaxis es otra: se rechaza en cualquier posición
		if slices.Contains(fields[1:], "system") {
			return denied(cmd, "playbook.why.probe_asa")
		}
		f := fields
		ok := validASAPing(f)
		if f[0] == "traceroute" {
			ok = validASATrace(f)
		}
		if !ok {
			return denied(cmd, "playbook.why.probe_asa")
		}
	case "packet-tracer":
		if !validASATracer(fields) {
			return denied(cmd, "playbook.why.tracer_asa")
		}
	default:
		return denied(cmd, "playbook.why.not_read")
	}
	return nil
}
