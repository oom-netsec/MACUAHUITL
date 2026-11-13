package i18n

// Playbooks y lista de lectura (internal/playbook): comandos rechazados y errores de los archivos YAML. Los
// comandos y los nombres de archivo son datos.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"playbook.err.denied":        e("playbook: comando no permitido en una recolección (solo lectura)", "playbook: command not allowed in a collection (read-only)"),
		"playbook.err.denied_cmd":    e("playbook: comando no permitido en una recolección (solo lectura): {cmd:q} ({cause})", "playbook: command not allowed in a collection (read-only): {cmd:q} ({cause})", "cmd", "cause"),
		"playbook.why.ascii":         e("solo ASCII imprimible; un retorno de carro o un carácter de 8 bits ejecutaría otro comando", "printable ASCII only; a carriage return or an 8-bit character would run another command"),
		"playbook.why.to_file":       e("to-file escribe en el equipo", "to-file writes to the device"),
		"playbook.why.terminal":      e("solo terminal length y terminal width", "only terminal length and terminal width"),
		"playbook.why.not_read":      e("no es un comando de lectura", "not a read command"),
		"playbook.why.empty_pipe":    e("pipe vacío", "empty pipe"),
		"playbook.why.pipe_sink":     e("redirect, tee y append escriben fuera de la sesión", "redirect, tee and append write outside the session"),
		"playbook.why.pipe_filter":   e("solo include, exclude, begin, section y count tras |", "only include, exclude, begin, section and count after |"),
		"playbook.why.cr_in_line":    e("retorno de carro dentro de la línea", "carriage return inside the line"),
		"playbook.err.file":          e("playbook {name}: {cause}", "playbook {name}: {cause}", "name", "cause"),
		"playbook.err.required":      e("id, platform y name son obligatorios", "id, platform and name are required"),
		"playbook.err.no_commands":   e("sin comandos", "no commands"),
		"playbook.err.platform":      e("plataforma desconocida {platform:q} en platforms de {cmd:q}", "unknown platform {platform:q} in platforms of {cmd:q}", "platform", "cmd"),
		"playbook.err.empty_command": e("comando vacío", "empty command"),
		"playbook.err.timeout":       e("timeout {timeout:q} inválido en {cmd:q}", "invalid timeout {timeout:q} in {cmd:q}", "timeout", "cmd"),
		"playbook.err.timeout_max":   e("timeout {timeout:q} de {cmd:q} pasa el máximo de {max}", "timeout {timeout:q} of {cmd:q} exceeds the maximum of {max}", "timeout", "cmd", "max"),
		"sys.err.not_regular":        e("la ruta no es un archivo regular", "the path is not a regular file"),
		"adhoc.err.no_targets":       e("indica al menos un equipo", "specify at least one device"),
		"playbook.err.none":          e("playbook: no hay comandos", "playbook: there are no commands"),
	})
}
