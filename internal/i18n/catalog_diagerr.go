package i18n

// Errores de internal/diag (argumentos de las herramientas y su ejecución). Los nombres de herramienta, destinos y
// los textos del sistema que cita el mensaje son datos y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"diag.err.target_bad":    e("destino {target:q} inválido", "invalid target {target:q}", "target"),
		"diag.err.no_cidr":       e("{target} no acepta rangos CIDR", "{target} does not accept CIDR ranges", "target"),
		"diag.err.prefix_bad":    e("prefijo {prefix:q} inválido", "invalid prefix {prefix:q}", "prefix"),
		"diag.err.target_kind":   e("destino {target:q} no es IP, nombre ni CIDR", "target {target:q} is not an IP, a name or a CIDR", "target"),
		"diag.err.one_of":        e("{key} debe ser uno de {values}", "{key} must be one of {values}", "key", "values"),
		"diag.err.number":        e("{key} debe ser un número entre {lo} y {hi}", "{key} must be a number between {lo} and {hi}", "key", "lo", "hi"),
		"diag.err.option":        e("opción {key:q} no existe para esta herramienta", "option {key:q} does not exist for this tool", "key"),
		"diag.err.one_target":    e("se necesita exactamente un destino", "exactly one target is needed"),
		"diag.err.ports":         e("ports {value:q} inválido; usa 22,80,443-445", "invalid ports {value:q}; use 22,80,443-445", "value"),
		"diag.err.iperf_client":  e("iperf3 cliente: {cause}", "iperf3 client: {cause}", "cause"),
		"diag.err.iperf_bind":    e("iperf3 servidor: bind {value:q} debe ser una IP de esta máquina (nunca todas las interfaces)", "iperf3 server: bind {value:q} must be an IP of this machine (never all interfaces)", "value"),
		"diag.err.pcap_target":   e("la captura no lleva destino; usa el filtro", "the capture takes no target; use the filter"),
		"diag.err.pcap_dir":      e("la captura necesita una carpeta de salida", "the capture needs an output folder"),
		"diag.err.pcap_iface":    e("interfaz inválida o ausente", "invalid or missing interface"),
		"diag.err.tool_unknown":  e("herramienta {tool:q} desconocida", "unknown tool {tool:q}", "tool"),
		"diag.err.flag_like":     e("el valor {value:q} parece una bandera", "the value {value:q} looks like a flag", "value"),
		"diag.err.not_installed": e("diag: herramienta no instalada", "diag: tool not installed"),
		"diag.err.install":       e("{cause}: {bin} (instala: sudo apt install {pkg})", "{cause}: {bin} (install: sudo apt install {pkg})", "cause", "bin", "pkg"),
		"diag.err.wrap":          e("diag: {cause}", "diag: {cause}", "cause"),
	})
}
