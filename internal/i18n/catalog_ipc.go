package i18n

// Errores del canal local del núcleo (internal/ipc): socket Unix en Linux, named pipe en Windows. Las variantes
// «.windows» solo cambian la palabra «socket» por «pipe» y usan los mismos argumentos que su base.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"ipc.err.already_running":         e("ipc: ya hay un núcleo escuchando en el socket", "ipc: a core is already listening on the socket"),
		"ipc.err.already_running.windows": e("ipc: ya hay un núcleo escuchando en el pipe", "ipc: a core is already listening on the pipe"),
		"ipc.err.not_running":             e("ipc: el núcleo no está corriendo", "ipc: the core is not running"),
		"ipc.err.runtime_dir":             e("ipc: XDG_RUNTIME_DIR no está definido; el núcleo corre como servicio de usuario de systemd", "ipc: XDG_RUNTIME_DIR is not set; the core runs as a systemd user service"),
		"ipc.err.socket_other_user":       e("ipc: el socket {path} lo atiende otro usuario o un PID inválido", "ipc: the socket {path} is served by another user or an invalid PID", "path"),
		"ipc.err.not_pipe":                e("ipc: la conexión no es un pipe", "ipc: the connection is not a pipe"),
		"ipc.err.pipe_no_owner":           e("ipc: el pipe no tiene dueño", "ipc: the pipe has no owner"),
		"ipc.err.pipe_not_user":           e("ipc: el pipe {name} no lo atiende un proceso de este usuario", "ipc: the pipe {name} is not served by a process of this user", "name"),
		"ipc.err.pipe_bad_pid":            e("ipc: el pipe {name} devolvió un PID inválido", "ipc: the pipe {name} returned an invalid PID", "name"),
		"ipc.err.server_low_integrity":    e("el servidor del pipe tiene menos integridad que este proceso, es AppContainer o tiene token restringido", "the pipe server has lower integrity than this process, is an AppContainer or has a restricted token"),
		"ipc.err.pipe_low_integrity":      e("ipc: el pipe {name} lo atiende un proceso de menor integridad, AppContainer o con token restringido", "ipc: the pipe {name} is served by a lower-integrity, AppContainer or restricted-token process", "name"),
		"ipc.err.server_not_user":         e("el servidor del pipe no es de este usuario", "the pipe server does not belong to this user"),
		"mctl.err.elevated":               e("mctl no habla con el núcleo desde una terminal elevada (el núcleo corre sin elevar); abre una terminal normal", "mctl does not talk to the core from an elevated terminal (the core runs unelevated); open a normal terminal"),
		"mctl.err.core_down":              e("el núcleo no está corriendo; arráncalo (app, o macuahuitld)", "the core is not running; start it (the app, or macuahuitld)"),
		"sys.err.log_not_regular":         e("{path}: no es un archivo regular", "{path}: is not a regular file", "path"),
		"core.err.prefs":                  e("core: preferencias: {cause}", "core: preferences: {cause}", "cause"),
		"core.err.packs":                  e("core: paquetes: {cause}", "core: packages: {cause}", "cause"),
	})
}
