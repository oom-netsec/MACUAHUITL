package i18n

// Análisis de capturas (internal/pcapan): encabezados de sección (pcap.section.*), avisos (pcap.warn.*) y las
// frases fijas del resumen de texto (pcap.text.*). Los valores (IPs, puertos, nombres, cifras) no pasan por aquí.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"pcap.section.neighbors":     e("Vecinos (¿a dónde estoy conectado?)", "Neighbors (what am I connected to?)"),
		"pcap.section.tcp":           e("TCP", "TCP"),
		"pcap.section.dns":           e("DNS", "DNS"),
		"pcap.section.tls":           e("TLS (SNI)", "TLS (SNI)"),
		"pcap.section.icmp":          e("ICMP", "ICMP"),
		"pcap.section.arp_conflict":  e("CONFLICTO ARP: {ip} anunciada por {macs}", "ARP CONFLICT: {ip} announced by {macs}", "ip", "macs"),
		"pcap.section.conversations": e("Conversaciones con más bytes", "Top conversations by bytes"),
		"pcap.section.top_talkers":   e("Equipos con más tráfico", "Top talkers"),

		"pcap.warn.truncated":   e("archivo truncado tras {packets} paquetes; el reporte es parcial", "file truncated after {packets} packets; the report is partial", "packets"),
		"pcap.warn.interrupted": e("lectura interrumpida tras {packets} paquetes: {error}", "read interrupted after {packets} packets: {error}", "packets", "error"),
		"pcap.warn.flow_limit":  e("la captura superó el límite de {max} flujos por tabla; los conteos por flujo son parciales", "the capture exceeded the limit of {max} flows per table; per-flow counts are partial", "max"),

		"pcap.text.file":           e("Captura: {file}", "Capture: {file}", "file"),
		"pcap.text.summary":        e("Paquetes: {packets} · Bytes: {bytes} · Duración: {duration} · Desde {start}", "Packets: {packets} · Bytes: {bytes} · Duration: {duration} · Since {start}", "packets", "bytes", "duration", "start"),
		"pcap.text.warning":        e("AVISO: {message}", "WARNING: {message}", "message"),
		"pcap.text.neighbor":       e("{protocol}  {device}  puerto {port}  {platform}  gestión {mgmt}  vlan nativa {vlan}", "{protocol}  {device}  port {port}  {platform}  management {mgmt}  native vlan {vlan}", "protocol", "device", "port", "platform", "mgmt", "vlan"),
		"pcap.text.handshakes":     e("Handshakes completos: {n} · RTT de handshake min/prom/máx: {min} / {avg} / {max}", "Complete handshakes: {n} · Handshake RTT min/avg/max: {min} / {avg} / {max}", "n", "min", "avg", "max"),
		"pcap.text.retransmits":    e("Retransmisiones: {retransmissions} · Ventana cero: {zero_window}", "Retransmissions: {retransmissions} · Zero window: {zero_window}", "retransmissions", "zero_window"),
		"pcap.text.failed_syn":     e("SYN sin respuesta ({n}):", "Unanswered SYN ({n}):", "n"),
		"pcap.text.failed_flow":    e("{client} → {server}  ({attempts} intentos)", "{client} → {server}  ({attempts} {attempts|attempt|attempts})", "client", "server", "attempts"),
		"pcap.text.reset":          e("RST: {client} ↔ {server}  ({count})", "RST: {client} ↔ {server}  ({count})", "client", "server", "count"),
		"pcap.text.dns_counts":     e("Consultas: {queries} · Respuestas: {responses}", "Queries: {queries} · Responses: {responses}", "queries", "responses"),
		"pcap.text.dns_error":      e("{rcode}  {name} {type}  servidor {server}", "{rcode}  {name} {type}  server {server}", "rcode", "name", "type", "server"),
		"pcap.text.dns_slow":       e("LENTA {latency}  {name} {type}  servidor {server}", "SLOW {latency}  {name} {type}  server {server}", "latency", "name", "type", "server"),
		"pcap.text.dns_unanswered": e("SIN RESPUESTA  {name} {type}  servidor {server}", "NO RESPONSE  {name} {type}  server {server}", "name", "type", "server"),
		"pcap.text.icmp_unreach":   e("Inalcanzable (código {code}): {from} avisa que {target} no se alcanza", "Unreachable (code {code}): {from} reports that {target} cannot be reached", "code", "from", "target"),
		"pcap.text.icmp_ttl":       e("TTL excedido: {from} hacia {target}", "TTL exceeded: {from} towards {target}", "from", "target"),
		"pcap.text.fragments":      e("Fragmentos IP: {n} (revisa MTU o túneles)", "IP fragments: {n} (check MTU or tunnels)", "n"),
		"pcap.text.counts":         e("{packets} paquetes  {bytes} bytes", "{packets} {packets|packet|packets}  {bytes} {bytes|byte|bytes}", "packets", "bytes"),
	})
}
