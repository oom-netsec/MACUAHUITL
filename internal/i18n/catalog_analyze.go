package i18n

// Análisis de trabajos de Patrol: detalle de los hallazgos, avisos, líneas de tiempo, diferencias entre rondas
// y el texto fijo de los informes. El título, la explicación y la acción de cada regla viven en el YAML de la
// regla (title_en, explanation_en, action_en); los valores (equipos, interfaces, líneas de log) no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		// detalle de los hallazgos
		"analyze.detail.lines":        e("{n} línea(s)", "{n} {n|line|lines}", "n"),
		"analyze.detail.group_count":  e("{group}: {n} veces", "{group}: {n} {n|time|times}", "group", "n"),
		"analyze.detail.cpu_high":     e("5 min: {pct}% (umbral {above}%)", "5 min: {pct}% (threshold {above}%)", "pct", "above"),
		"analyze.detail.cpu_trend":    e("5 min por ronda: {vals}", "5 min per round: {vals}", "vals"),
		"analyze.detail.mem_low":      e("libre {pct}% de {total} bytes (umbral {below}%)", "{pct}% free of {total} bytes (threshold {below}%)", "pct", "total", "below"),
		"analyze.detail.mem_leak":     e("libre por ronda: {vals} (bajó {lost} puntos)", "free per round: {vals} (dropped {lost} points)", "vals", "lost"),
		"analyze.detail.counter_grow": e("{name}: {from} → {to} (+{delta})", "{name}: {from} → {to} (+{delta})", "name", "from", "to", "delta"),
		"analyze.detail.counter_val":  e("{name}: {value}", "{name}: {value}", "name", "value"),
		"analyze.detail.up_since":     e("arriba desde hace {dur}", "up for {dur}", "dur"),
		"analyze.detail.uptime_reset": e("uptime {from} → {to}", "uptime {from} → {to}", "from", "to"),
		"analyze.detail.stp_changes":  e("{name}: {n} cambios", "{name}: {n} {n|change|changes}", "name", "n"),
		"analyze.detail.stp_grew":     e("{name}: {from} → {to} cambios", "{name}: {from} → {to} changes", "name", "from", "to"),
		"analyze.detail.stp_last":     e(", último hace {since}", ", last {since} ago", "since"),
		"analyze.detail.stp_from":     e(" desde {from}", " from {from}", "from"),
		"analyze.detail.bgp_down":     e("{id} (AS {as}): {state} desde hace {updown}", "{id} (AS {as}): {state} for {updown}", "id", "as", "state", "updown"),
		"analyze.detail.bgp_flap":     e("{id} (AS {as}): arriba hace {updown}", "{id} (AS {as}): up for {updown}", "id", "as", "updown"),
		"analyze.detail.ospf_stuck":   e("{id} en {state} por {iface}", "{id} in {state} on {iface}", "id", "state", "iface"),
		"analyze.detail.ospf_lost":    e("{key} estaba en la ronda {round} y ya no aparece", "{key} was present in round {round} and no longer appears", "key", "round"),
		"analyze.detail.hsrp_changed": e("{key}: {from} → {to}", "{key}: {from} → {to}", "key", "from", "to"),
		"analyze.detail.hsrp_bad":     e("{key}: {state} (activo {active}, respaldo {standby})", "{key}: {state} (active {active}, standby {standby})", "key", "state", "active", "standby"),

		// avisos
		"analyze.warn.format":           e("formato inesperado: sin datos para esta regla", "unexpected format: no data for this rule"),
		"analyze.warn.format_missing":   e("formato inesperado: sin datos para esta regla (falta {what:q})", "unexpected format: no data for this rule ({what:q} is missing)", "what"),
		"analyze.warn.format_no_pool":   e("formato inesperado: sin datos para esta regla (falta el pool Processor)", "unexpected format: no data for this rule (the Processor pool is missing)"),
		"analyze.warn.format_no_ifaces": e("formato inesperado: sin datos para esta regla (ninguna interfaz reconocida)", "unexpected format: no data for this rule (no interface recognized)"),
		"analyze.warn.format_no_nbrs":   e("formato inesperado: sin datos para esta regla (falta la tabla de vecinos)", "unexpected format: no data for this rule (the neighbor table is missing)"),
		"analyze.warn.format_no_groups": e("formato inesperado: sin datos para esta regla (falta la tabla de grupos)", "unexpected format: no data for this rule (the group table is missing)"),
		"analyze.warn.rejected":         e("el equipo rechazó el comando; sin datos para las reglas que lo usan", "the device rejected the command; no data for the rules that use it"),
		"analyze.warn.system":           e("{error}", "{error}", "error"),
		"analyze.warn.file_error":       e("{file}: {error}", "{file}: {error}", "file", "error"),
		"analyze.warn.over_total":       e("el paquete supera el tope de {mib} MiB descomprimidos: se leyó parcialmente y los hallazgos pueden estar incompletos (usa --round o --device)", "the package exceeds the {mib} MiB uncompressed limit: it was read partially and the findings may be incomplete (use --round or --device)", "mib"),
		"analyze.warn.trimmed":          e("salida recortada a {bytes} bytes", "output trimmed to {bytes} bytes", "bytes"),
		"analyze.warn.no_outputs":       e("sin salidas en la ronda {from} o {to}", "no outputs in round {from} or {to}", "from", "to"),
		"analyze.warn.uptime_stamps":    e("{n} mensaje(s) con marca de uptime, sin hora absoluta: se omiten (configura service timestamps log datetime msec)", "{n} {n|message|messages} with an uptime stamp and no absolute time: omitted (configure service timestamps log datetime msec)", "n"),
		"analyze.warn.log_no_zone":      e("hora del log sin referencia de zona: sin show clock detail se toma como UTC (recolecta show clock detail o usa show-timezone)", "log time has no timezone reference: without show clock detail it is taken as UTC (collect show clock detail or use show-timezone)"),
		"analyze.warn.syslog_bad_lines": e("{name}: {n} línea(s) sin el formato del receptor syslog", "{name}: {n} {n|line|lines} not in the syslog receiver format", "name", "n"),
		"analyze.warn.syslog_cap":       e("syslog: tope de {mib} MiB leído; el resto de {file} y los archivos siguientes se omiten", "syslog: {mib} MiB limit read; the rest of {file} and the following files are omitted", "mib", "file"),
		"analyze.warn.audit":            e("auditoría: {error}", "audit: {error}", "error"),
		"analyze.warn.pcap":             e("pcap: {message}", "pcap: {message}", "message"),

		// eventos de la línea de tiempo
		"analyze.event.round":        e("ronda {round}: {n} comando(s)", "round {round}: {n} {n|command|commands}", "round", "n"),
		"analyze.event.finding":      e("{title} (ronda {round}): {detail}", "{title} (round {round}): {detail}", "title", "round", "detail"),
		"analyze.event.by":           e("por {actor}", "by {actor}", "actor"),
		"analyze.event.clock_unsync": e("reloj sin sincronizar en el equipo", "device clock not synchronized"),
		"analyze.event.local_to_utc": e("hora local del equipo pasada a UTC con show clock detail (desfase {offset})", "device local time converted to UTC with show clock detail (offset {offset})", "offset"),
		"analyze.event.local_raw":    e("hora local del equipo ({zone}), sin convertir a UTC", "device local time ({zone}), not converted to UTC", "zone"),
		"analyze.event.rst":          e("RST {client} → {server}", "RST {client} → {server}", "client", "server"),
		"analyze.event.retransmit":   e("retransmisión {client} → {server}", "retransmission {client} → {server}", "client", "server"),
		"analyze.event.dns_slow":     e("DNS lento {name} {type} ({latency}) {client} → {server}", "slow DNS {name} {type} ({latency}) {client} → {server}", "name", "type", "latency", "client", "server"),
		"analyze.event.dns_error":    e("DNS {rcode} {name} {type}", "DNS {rcode} {name} {type}", "rcode", "name", "type"),
		"analyze.event.dns_none":     e("DNS sin respuesta {name} {type} {client} → {server}", "DNS unanswered {name} {type} {client} → {server}", "name", "type", "client", "server"),
		"analyze.event.icmp_unreach": e("ICMP inalcanzable (código {code}) de {from} para {target}", "ICMP unreachable (code {code}) from {from} for {target}", "code", "from", "target"),
		"analyze.event.icmp_ttl":     e("ICMP TTL excedido de {from} para {target}", "ICMP TTL exceeded from {from} for {target}", "from", "target"),

		// diferencias entre rondas
		"analyze.diff.only_in":    e("solo en la ronda {round}", "only in round {round}", "round"),
		"analyze.diff.too_big":    e("demasiado distinto para comparar línea a línea ({a} contra {b} líneas)", "too different to compare line by line ({a} against {b} lines)", "a", "b"),
		"analyze.diff.more_lines": e("{n} líneas más sin mostrar", "{n} more {n|line|lines} not shown", "n"),

		// texto fijo de los informes
		"analyze.sev.critica":      e("CRÍTICA", "CRITICAL"),
		"analyze.sev.alta":         e("ALTA", "HIGH"),
		"analyze.sev.media":        e("MEDIA", "MEDIUM"),
		"analyze.sev.baja":         e("BAJA", "LOW"),
		"analyze.sev.info":         e("INFO", "INFO"),
		"analyze.text.summary":     e("equipos: {devices} · rondas: {rounds} · hallazgos: {n}", "devices: {devices} · rounds: {rounds} · findings: {n}", "devices", "rounds", "n"),
		"analyze.text.finding":     e("[{sev}] {title} — {device} · ronda {round} · {at}", "[{sev}] {title} — {device} · round {round} · {at}", "sev", "title", "device", "round", "at"),
		"analyze.text.evidence":    e("evidencia ({cmd}):", "evidence ({cmd}):", "cmd"),
		"analyze.text.why":         e("por qué: {text}", "why: {text}", "text"),
		"analyze.text.action":      e("qué hacer: {text}", "what to do: {text}", "text"),
		"analyze.text.missing":     e("no recolectados (reglas sin datos): {cmds}", "not collected (rules without data): {cmds}", "cmds"),
		"analyze.text.warning":     e("aviso: {message}", "warning: {message}", "message"),
		"analyze.text.unvalidated": e("Reglas sin validar en laboratorio: confirma cada hallazgo con la evidencia.", "Rules not validated in the lab: confirm each finding against the evidence."),
		"analyze.text.round":       e("ronda {round}", "round {round}", "round"),
		"analyze.text.rounds":      e("ronda {from} → ronda {to}", "round {from} → round {to}", "from", "to"),
		"analyze.text.reload":      e("  ← RECARGÓ", "  ← RELOADED"),
		"analyze.text.counter":     e("contador {iface} {counter}: {from} → {to} ({delta})", "counter {iface} {counter}: {from} → {to} ({delta})", "iface", "counter", "from", "to", "delta"),
		"analyze.text.prefixes":    e("prefijos de {neighbor}: {from} → {to}", "prefixes from {neighbor}: {from} → {to}", "neighbor", "from", "to"),
		"analyze.text.window":      e("ventana: {around} ± {window}", "window: {around} ± {window}", "around", "window"),
	})
}

func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"analyze.key.ospf":           e("{id} por {iface}", "{id} on {iface}", "id", "iface"),
		"analyze.key.hsrp":           e("{iface} grupo {group}", "{iface} group {group}", "iface", "group"),
		"analyze.change.appeared":    e("apareció", "appeared"),
		"analyze.change.disappeared": e("desapareció", "disappeared"),
		"analyze.change.changed":     e("cambió", "changed"),
	})
}

// Errores gRPC y de carga del análisis y de la deriva (comparten el paquete de salidas de un trabajo).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"analyze.err.job_no_outputs": e("el trabajo aún no tiene salidas: ármalo y espera la primera ronda", "the job has no outputs yet: arm it and wait for the first round"),
		"analyze.err.pcap_path":      e("la ruta de la captura debe ser absoluta", "the capture path must be absolute"),
		"analyze.err.rounds":         e("analyze: el trabajo tiene las rondas {have}; no hay {from} o {to}", "analyze: the job has rounds {have}; there is no {from} or {to}", "have", "from", "to"),
		"analyze.err.not_dir":        e("analyze: {path} no es una carpeta", "analyze: {path} is not a folder", "path"),
		"analyze.err.no_outputs":     e("analyze: {path} no contiene salidas de Patrol", "analyze: {path} has no Patrol outputs", "path"),
		"analyze.err.read":           e("analyze: {cause}", "analyze: {cause}", "cause"),
	})
}
