package i18n

// Errores de internal/diag (argumentos de las herramientas y su ejecución). Los nombres de herramienta, destinos y
// los textos del sistema que cita el mensaje son datos y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"diag.err.target_bad":        e("destino {target:q} inválido", "invalid target {target:q}", "target"),
		"diag.err.no_cidr":           e("{target} no acepta rangos CIDR", "{target} does not accept CIDR ranges", "target"),
		"diag.err.prefix_bad":        e("prefijo {prefix:q} inválido", "invalid prefix {prefix:q}", "prefix"),
		"diag.err.target_kind":       e("destino {target:q} no es IP, nombre ni CIDR", "target {target:q} is not an IP, a name or a CIDR", "target"),
		"diag.err.one_of":            e("{key} debe ser uno de {values}", "{key} must be one of {values}", "key", "values"),
		"diag.err.number":            e("{key} debe ser un número entre {lo} y {hi}", "{key} must be a number between {lo} and {hi}", "key", "lo", "hi"),
		"diag.err.option":            e("opción {key:q} no existe para esta herramienta", "option {key:q} does not exist for this tool", "key"),
		"diag.err.one_target":        e("se necesita exactamente un destino", "exactly one target is needed"),
		"diag.err.ports":             e("ports {value:q} inválido; usa 22,80,443-445", "invalid ports {value:q}; use 22,80,443-445", "value"),
		"diag.err.iperf_client":      e("iperf3 cliente: {cause}", "iperf3 client: {cause}", "cause"),
		"diag.err.iperf_bind":        e("el servidor de iperf3 necesita la IP local de esta máquina en la opción bind (nunca todas las interfaces; no link-local); se recibió {value:q}", "the iperf3 server needs this machine's local IP in the bind option (never all interfaces; not link-local); got {value:q}", "value"),
		"diag.err.pcap_target":       e("la captura no lleva destino; usa el filtro", "the capture takes no target; use the filter"),
		"diag.err.pcap_dir":          e("la captura necesita una carpeta de salida", "the capture needs an output folder"),
		"diag.err.pcap_iface":        e("interfaz inválida o ausente", "invalid or missing interface"),
		"diag.err.tool_unknown":      e("herramienta {tool:q} desconocida", "unknown tool {tool:q}", "tool"),
		"diag.err.flag_like":         e("el valor {value:q} parece una bandera", "the value {value:q} looks like a flag", "value"),
		"diag.err.not_installed":     e("diag: herramienta no instalada", "diag: tool not installed"),
		"diag.err.install":           e("{cause}: {bin} (instala: sudo apt install {pkg})", "{cause}: {bin} (install: sudo apt install {pkg})", "cause", "bin", "pkg"),
		"diag.err.install_win":       e("{cause}: {bin} (descárgalo de {url})", "{cause}: {bin} (download it from {url})", "cause", "bin", "url"),
		"diag.err.install_iperf_win": e(`{cause}: iperf3 no tiene versión oficial para Windows; descarga una compilación de confianza y ponla en %ProgramFiles%\iperf3\iperf3.exe o en tools\iperf3.exe junto a macuahuitld.exe`, `{cause}: iperf3 has no official Windows build; download a build you trust and put it in %ProgramFiles%\iperf3\iperf3.exe or in tools\iperf3.exe next to macuahuitld.exe`, "cause"),
		"diag.err.install_sys_win":   e(`{cause}: {bin} (debería estar en %SystemRoot%\System32)`, `{cause}: {bin} (it should be in %SystemRoot%\System32)`, "cause", "bin"),
		"diag.err.opt_windows":       e("la opción {key:q} no existe en Windows para esta herramienta", "option {key:q} does not exist on Windows for this tool", "key"),
		"diag.err.syn_windows":       e("el escaneo SYN de nmap no está disponible en Windows (necesita Npcap); usa connect", "the nmap SYN scan is not available on Windows (it needs Npcap); use connect"),
		"diag.err.wrap":              e("diag: {cause}", "diag: {cause}", "cause"),
	})
}
