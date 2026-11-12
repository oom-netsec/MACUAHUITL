package i18n

// Validación de los receptores de eventos (syslog, traps SNMP y flujos). Todos comparten el motivo
// ingest.invalid; la metadata dice qué campo falló ({field}) y, según el caso, el rango ({min}, {max}), el valor
// o el problema de la plantilla ({template_problem}).
func init() {
	m := map[string]entry{}
	inv := func(key, field string, e entry, meta ...string) {
		e.Reason = "ingest.invalid"
		e.Meta = map[string]string{"field": field}
		for i := 0; i+1 < len(meta); i += 2 {
			e.Meta[meta[i]] = meta[i+1]
		}
		m["ingest.invalid."+key] = e
	}
	// Topes numéricos: el texto lleva el valor recibido.
	for _, f := range []struct{ field, es, en, min, max string }{
		{"rate_per_source", "la tasa por origen", "the per-source rate", "1", "10000"},
		{"burst_per_source", "la ráfaga por origen", "the per-source burst", "1", "1000000"},
		{"rate_global", "la tasa global", "the global rate", "1", "100000"},
		{"burst_global", "la ráfaga global", "the global burst", "1", "1000000"},
		{"queue_size", "la cola", "the queue size", "64", "65536"},
	} {
		inv(f.field, f.field, entry{Es: f.es + " debe estar entre {min} y {max} (0 = default), no {value}",
			En: f.en + " must be between {min} and {max} (0 = default), not {value}", Args: []string{"min", "max", "value"}})
	}
	inv("dir", "dir", entry{Es: "falta la carpeta de salida", En: "the output folder is missing"})
	inv("rotate_mb", "rotate_mb", entry{Es: "el tamaño de rotación debe estar entre 1 y 1024 MB", En: "the rotation size must be between 1 and 1024 MB"}, "min", "1", "max", "1024")
	inv("rotate_minutes", "rotate_minutes", entry{Es: "la rotación por tiempo debe estar entre 1 minuto y 7 días", En: "the time-based rotation must be between 1 minute and 7 days"}, "min", "1", "max", "10080")
	inv("max_files", "max_files", entry{Es: "el máximo de archivos debe estar entre 1 y 1000", En: "the maximum number of files must be between 1 and 1000"}, "min", "1", "max", "1000")
	inv("format", "format", entry{Es: "formato {value:q} no soportado (texto, crudo o jsonl)", En: "format {value:q} is not supported (texto, crudo or jsonl)", Args: []string{"value"}})
	inv("protocol", "protocol", entry{Es: "syslogd: protocolo {value:q} no soportado (udp o tcp)", En: "syslogd: protocol {value:q} is not supported (udp or tcp)", Args: []string{"value"}})
	// Plantilla del nombre del archivo: {template_problem} dice cuál regla rompe.
	inv("name_template.len", "name_template", entry{Es: "la plantilla debe tener entre 1 y 64 caracteres", En: "the template must be between 1 and 64 characters long"}, "template_problem", "len", "min", "1", "max", "64")
	inv("name_template.need", "name_template", entry{Es: "la plantilla debe llevar {{fecha}} o {{hora}}", En: "the template must contain {{date}} or {{time}}"}, "template_problem", "need")
	inv("name_template.tokens", "name_template", entry{Es: "la plantilla solo admite los tokens {{fecha}}, {{hora}} y {{origen}}, bien cerrados", En: "the template only accepts the tokens {{date}}, {{time}} and {{source}}, properly closed"}, "template_problem", "tokens")
	inv("name_template.chars", "name_template", entry{Es: "la plantilla solo admite letras, dígitos, _ . - y los tokens; no {ch}", En: "the template only accepts letters, digits, _ . - and the tokens; not {ch}", Args: []string{"ch"}}, "template_problem", "chars")
	inv("name_template.dots", "name_template", entry{Es: `la plantilla no puede llevar ".."`, En: `the template cannot contain ".."`}, "template_problem", "dots")
	// Dirección de escucha: la de syslog y la de traps y flujos (listen) tienen textos propios.
	inv("addr.parse", "addr", entry{Es: "syslogd: dirección inválida {addr:q}: {detail}", En: "syslogd: invalid address {addr:q}: {detail}", Args: []string{"addr", "detail"}})
	inv("addr.port", "addr", entry{Es: "syslogd: puerto inválido {port:q}", En: "syslogd: invalid port {port:q}", Args: []string{"port"}})
	inv("addr.privileged", "addr", entry{Es: "syslogd: el puerto {port} es privilegiado; usa uno alto (p. ej. 5514) y redirige si hace falta", En: "syslogd: port {port} is privileged; use a high one (e.g. 5514) and redirect if needed", Args: []string{"port"}})
	inv("addr.host", "addr", entry{Es: "syslogd: el host debe ser una IP local, no {host:q}", En: "syslogd: the host must be a local IP, not {host:q}", Args: []string{"host"}})
	inv("addr.any", "addr", entry{Es: "syslogd: escuchar en todas las interfaces requiere pedirlo explícitamente", En: "syslogd: listening on all interfaces must be requested explicitly"})
	inv("listen.parse", "addr", entry{Es: "dirección de escucha inválida {addr:q}: {detail}", En: "invalid listen address {addr:q}: {detail}", Args: []string{"addr", "detail"}})
	inv("listen.port", "addr", entry{Es: "puerto inválido {port:q}", En: "invalid port {port:q}", Args: []string{"port"}})
	inv("listen.privileged", "addr", entry{Es: "el puerto {port} es privilegiado; escucha en uno alto y, si el equipo no permite cambiar el destino, redirige con nftables (docs/plans/2026-11-04-fase-12-visibilidad.md)", En: "port {port} is privileged; listen on a high one and, if the device cannot change the destination, redirect with nftables (docs/plans/2026-11-04-fase-12-visibilidad.md)", Args: []string{"port"}})
	inv("listen.host", "addr", entry{Es: "el host debe ser una IP local, no {host:q}", En: "the host must be a local IP, not {host:q}", Args: []string{"host"}})
	inv("listen.any", "addr", entry{Es: "escuchar en todas las interfaces requiere pedirlo explícitamente", En: "listening on all interfaces must be requested explicitly"})
	add(m)
}
