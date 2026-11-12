package i18n

// Diagnóstico DNS (internal/diag/dnsq): detalle de los hallazgos de transporte, higiene, zona y exposición
// (dns.finding.*). Los nombres, IPs, registros y errores del sistema que cita el texto son datos y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"dns.finding.fragmentation": e("respuesta UDP de {size} bytes: se fragmenta y muchos firewalls la descartan", "UDP response of {size} bytes: it gets fragmented and many firewalls drop it", "size"),
		"dns.finding.tcp_blocked":   e("TCP/53 no responde: las respuestas grandes y DNSSEC fallarán", "TCP/53 does not respond: large responses and DNSSEC will fail"),
		"dns.finding.no_edns":       e("el servidor no anuncia EDNS(0)", "the server does not advertise EDNS(0)"),
		"dns.finding.low_ttl":       e("{name} con TTL {ttl} s", "{name} with TTL {ttl} s", "name", "ttl"),
		"dns.finding.long_cname":    e("cadena de {n} CNAME", "chain of {n} CNAMEs", "n"),
		"dns.finding.no_ptr":        e("{ip} no tiene PTR", "{ip} has no PTR", "ip"),
		"dns.finding.ptr_mismatch":  e("{ip} → PTR {ptr}, pero ese nombre no resuelve de vuelta a {ip}", "{ip} → PTR {ptr}, but that name does not resolve back to {ip}", "ip", "ptr"),
		"dns.finding.no_spf":        e("no hay registro SPF", "there is no SPF record"),
		"dns.finding.multiple_spf":  e("hay varios SPF; los receptores lo tratan como error permanente", "there are several SPF records; receivers treat that as a permanent error"),
		"dns.finding.no_dmarc":      e("no hay registro DMARC en _dmarc.{name}", "there is no DMARC record at _dmarc.{name}", "name"),
		"dns.finding.no_dkim":       e("no hay llave DKIM en {key}", "there is no DKIM key at {key}", "key"),
		"dns.finding.no_caa":        e("sin CAA: cualquier autoridad puede emitir certificados para este nombre", "no CAA: any authority can issue certificates for this name"),

		"dns.finding.no_delegation":   e("el padre no delega la zona", "the parent does not delegate the zone"),
		"dns.finding.ns_parent_child": e("el padre anuncia {parent} y la zona anuncia {child}", "the parent advertises {parent} and the zone advertises {child}", "parent", "child"),
		"dns.finding.missing_glue":    e("{name} está dentro de la zona y el padre no da su dirección", "{name} is inside the zone and the parent does not give its address", "name"),
		"dns.finding.ns_unreachable":  e("{name} ({ip}) no responde: {error}", "{name} ({ip}) does not respond: {error}", "name", "ip", "error"),
		"dns.finding.ns_not_auth":     e("{name} ({ip}) no es autoritativo para la zona ({rcode}, AA={aa})", "{name} ({ip}) is not authoritative for the zone ({rcode}, AA={aa})", "name", "ip", "rcode", "aa"),
		"dns.finding.axfr_open":       e("{name} ({ip}) entrega la zona completa por AXFR a cualquiera", "{name} ({ip}) hands the whole zone to anyone by AXFR", "name", "ip"),
		"dns.finding.serial_mismatch": e("los autoritativos no están sincronizados: {servers}", "the authoritative servers are out of sync: {servers}", "servers"),

		"dns.exposure.open_resolver": e("resuelve nombres ajenos con recursión: resolvedor abierto (riesgo de amplificación)", "resolves third-party names with recursion: open resolver (amplification risk)"),
		"dns.exposure.nx_hijack":     e("responde con direcciones para un nombre que no puede existir: secuestro de NXDOMAIN", "answers with addresses for a name that cannot exist: NXDOMAIN hijacking"),
	})
}
