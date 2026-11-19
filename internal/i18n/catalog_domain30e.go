package i18n

// Errores de dominio que llegan al usuario (capture, transport, patrol, scripts, engine y las reglas YAML de analyze).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"capture.err.not_finished":      e("capture: {dir} no es una captura terminada de Patrol: {cause}", "capture: {dir} is not a finished Patrol capture: {cause}", "cause", "dir"),
		"transport.err.key_credential":  e("transport: la credencial es de solo llave: solo sirve para el terminal de hosts linux y windows", "transport: the credential is key-only: it only works for the terminal of linux and windows hosts"),
		"transport.err.typed_mixed":     e("transport: una credencial tecleada no se mezcla con una guardada", "transport: a typed credential cannot be mixed with a stored one"),
		"transport.err.no_credential":   e("transport: la credencial no trae contraseña ni llave", "transport: the credential has neither a password nor a key"),
		"transport.err.auth_attempts":   e("transport: autenticación rechazada tras 3 intentos", "transport: authentication rejected after 3 attempts"),
		"transport.err.auth_rounds":     e("transport: el equipo pidió demasiadas rondas de autenticación", "transport: the device asked for too many authentication rounds"),
		"transport.err.typed_no_method": e("transport: el equipo no ofrece password ni keyboard-interactive", "transport: the device offers neither password nor keyboard-interactive"),
		"transport.err.typed_prompt":    e("transport: el equipo mandó preguntas inválidas o desmedidas", "transport: the device sent invalid or oversized prompts"),
		"transport.err.no_shell":        e("transport: sin shell abierto", "transport: no shell is open"),
		"transport.err.known_hosts_ln":  e("{cause}: línea {n}", "{cause}: line {n}", "cause", "n"),
		"patrol.err.zip_not_regular":    e("{file} no es un archivo regular", "{file} is not a regular file", "file"),
		"scripts.err.no_library":        e("no hay scripts en la biblioteca para el ejemplo", "there are no scripts in the library for the example"),
		"scripts.err.kind":              e("tipo {kind:q} desconocido: scripts o colecciones", "unknown type {kind:q}: scripts or collections", "kind"),
		"engine.err.job_ended":          e("engine: el fin del trabajo ya pasó", "engine: the job's end time has already passed"),
		"engine.err.armed":              e("engine: {job} ya está armado", "engine: {job} is already armed", "job"),

		"rules.err.file":          e("reglas {file}: {cause}", "rules {file}: {cause}", "cause", "file"),
		"rules.err.rule":          e("reglas {file}: {id}: {cause}", "rules {file}: {id}: {cause}", "cause", "file", "id"),
		"rules.err.dup":           e("reglas {file}: id {id} repetido", "rules {file}: duplicate id {id}", "file", "id"),
		"rules.err.required":      e("id, title, explanation y action son obligatorios", "id, title, explanation and action are required"),
		"rules.err.severity":      e("severidad {sev:q} inválida (critica, alta, media, baja, info)", "invalid severity {sev:q} (critica, alta, media, baja, info)", "sev"),
		"rules.err.no_commands":   e("sin comandos", "no commands"),
		"rules.err.check":         e("check {check:q} desconocido", "unknown check {check:q}", "check"),
		"rules.err.param_unused":  e("parámetro {key:q} no aplica a {check}", "parameter {key:q} does not apply to {check}", "key", "check"),
		"rules.err.param_num":     e("parámetro {key}: {value:q} no es un número", "parameter {key}: {value:q} is not a number", "key", "value"),
		"rules.err.param_dur":     e("parámetro {key}: {value:q} no es una duración", "parameter {key}: {value:q} is not a duration", "key", "value"),
		"rules.err.param_bool":    e("parámetro {key}: {value:q} no es true/false", "parameter {key}: {value:q} is not true/false", "key", "value"),
		"rules.err.param_oneof":   e("parámetro {key}: {value:q} debe ser uno de {opts}", "parameter {key}: {value:q} must be one of {opts}", "key", "value", "opts"),
		"rules.err.pattern":       e("pattern inválido: {cause}", "invalid pattern: {cause}", "cause"),
		"rules.err.pattern_empty": e("pattern inválido: vacío", "invalid pattern: empty"),
		"rules.err.exclude":       e("exclude inválido: {cause}", "invalid exclude: {cause}", "cause"),
	})
}
