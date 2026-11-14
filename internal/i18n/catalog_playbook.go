package i18n

// Playbooks y lista de lectura (internal/playbook): comandos rechazados y errores de los archivos YAML. Los
// comandos y los nombres de archivo son datos.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"playbook.err.denied":           e("playbook: comando no permitido en una recolección (solo lectura)", "playbook: command not allowed in a collection (read-only)"),
		"playbook.err.denied_cmd":       e("playbook: comando no permitido en una recolección (solo lectura): {cmd:q} ({cause})", "playbook: command not allowed in a collection (read-only): {cmd:q} ({cause})", "cmd", "cause"),
		"playbook.why.ascii":            e("solo ASCII imprimible; un retorno de carro o un carácter de 8 bits ejecutaría otro comando", "printable ASCII only; a carriage return or an 8-bit character would run another command"),
		"playbook.why.to_file":          e("to-file escribe en el equipo", "to-file writes to the device"),
		"playbook.why.probe":            e("ping y traceroute solo admiten destino y opciones acotadas (repeat ≤ 10, size ≤ 1500, timeout 1-10, source, vrf, ttl, probe)", "ping and traceroute only accept a destination and bounded options (repeat ≤ 10, size ≤ 1500, timeout 1-10, source, vrf, ttl, probe)"),
		"playbook.why.terminal":         e("solo terminal length y terminal width", "only terminal length and terminal width"),
		"playbook.why.not_read":         e("no es un comando de lectura", "not a read command"),
		"playbook.why.empty_pipe":       e("pipe vacío", "empty pipe"),
		"playbook.why.remote":           e("ruta remota (ftp:, tftp:, http:, scp:…): el equipo se conectaría a otro servidor", "remote path (ftp:, tftp:, http:, scp:…): the device would connect to another server"),
		"playbook.why.pipe_sink":        e("redirect, tee y append escriben fuera de la sesión", "redirect, tee and append write outside the session"),
		"playbook.why.pipe_filter":      e("solo include, exclude, begin, section y count tras |", "only include, exclude, begin, section and count after |"),
		"playbook.why.redirect":         e("> y >> escriben en el equipo", "> and >> write to the device"),
		"playbook.why.chain":            e("«;» encadena comandos (NX-OS ejecuta cada parte)", "«;» chains commands (NX-OS runs each part)"),
		"playbook.why.subst":            e("«`», «$(» y las variables «$» sustituyen texto en el equipo", "«`», «$(» and «$» variables substitute text on the device"),
		"playbook.why.quote":            e("comillas dobles sin cerrar o fuera de lugar (solo abren al inicio de una palabra y cierran antes de un espacio, «|» o el fin)", "unclosed or misplaced double quote (they only open at the start of a word and close before a space, «|» or the end)"),
		"playbook.why.write_nxos":       e("binary, tar, compressed y gzip hacen que show tech-support escriba en el equipo", "binary, tar, compressed and gzip make show tech-support write to the device"),
		"playbook.why.pipe_shell":       e("sed, awk, python, bash, run, source, tclsh, vsh, email, diff, less, xargs, perl, sscp, cut y tr (o su abreviatura) no son filtros de lectura", "sed, awk, python, bash, run, source, tclsh, vsh, email, diff, less, xargs, perl, sscp, cut and tr (or an abbreviation) are not read filters"),
		"playbook.why.pipe_filter_nxos": e("tras cada | solo include, exclude, begin, section, count, grep, egrep, head, last, wc, sort, uniq, json, json-pretty, xml, no-more o end (escritos completos; una alternancia va entre comillas dobles) con sus argumentos: sin ninguno en count, wc, no-more, json, json-pretty, xml, end, sort y uniq; un número en head y last; un patrón (y opciones de una lista cerrada) en include, exclude, begin, section, grep y egrep; nunca un archivo (bootflash:, volatile:, /ruta)", "after every | only include, exclude, begin, section, count, grep, egrep, head, last, wc, sort, uniq, json, json-pretty, xml, no-more or end (spelled out; an alternation goes in double quotes) with their arguments: none for count, wc, no-more, json, json-pretty, xml, end, sort and uniq; a number for head and last; a pattern (and options from a closed list) for include, exclude, begin, section, grep and egrep; never a file (bootflash:, volatile:, /path)"),
		"playbook.why.probe_nxos":       e("ping y traceroute de NX-OS: destino (que no sea una palabra clave) y opciones acotadas: vrf, source, source-interface y, solo en ping, count ≤ 10, packet-size ≤ 1500, timeout 1-10", "NX-OS ping and traceroute: a destination (not a keyword) and bounded options: vrf, source, source-interface and, ping only, count ≤ 10, packet-size ≤ 1500, timeout 1-10"),
		"playbook.why.cr_in_line":       e("retorno de carro dentro de la línea", "carriage return inside the line"),
		"playbook.err.file":             e("playbook {name}: {cause}", "playbook {name}: {cause}", "name", "cause"),
		"playbook.err.required":         e("id, platform y name son obligatorios", "id, platform and name are required"),
		"playbook.err.no_commands":      e("sin comandos", "no commands"),
		"playbook.err.platform":         e("plataforma desconocida {platform:q} en platforms de {cmd:q}", "unknown platform {platform:q} in platforms of {cmd:q}", "platform", "cmd"),
		"playbook.err.empty_command":    e("comando vacío", "empty command"),
		"playbook.err.text":             e("{field} lleva caracteres de control o de dirección (bidi) que cambian cómo se ve el texto", "{field} contains control or direction (bidi) characters that change how the text looks", "field"),
		"playbook.err.timeout":          e("timeout {timeout:q} inválido en {cmd:q}", "invalid timeout {timeout:q} in {cmd:q}", "timeout", "cmd"),
		"playbook.err.timeout_max":      e("timeout {timeout:q} de {cmd:q} pasa el máximo de {max}", "timeout {timeout:q} of {cmd:q} exceeds the maximum of {max}", "timeout", "cmd", "max"),
		"sys.err.not_regular":           e("la ruta no es un archivo regular", "the path is not a regular file"),
		"adhoc.err.no_targets":          e("indica al menos un equipo", "specify at least one device"),
		"adhoc.err.max":                 e("adhoc: {n} comandos; el máximo es {max}. El tope es de diseño: cada comando es una ida y vuelta por equipo y un lote largo acapara la sesión del equipo; divide el lote en tandas de {max} comandos o menos y ejecútalas una tras otra", "adhoc: {n} commands; the maximum is {max}. The cap is by design: every command is a round trip per device and a long batch ties up the device session; split the batch into runs of {max} commands or fewer and run them one after another", "n", "max"),
		"adhoc.err.node_stopped":        e("el núcleo se detuvo con el lote en curso; vuelve a lanzarlo", "the core stopped with the batch in progress; launch it again"),
		"adhoc.err.no_dir":              e("el lote no conserva su carpeta de salida", "the batch no longer has its output folder"),
		"playbook.err.none":             e("playbook: no hay comandos", "playbook: there are no commands"),
	})
}
