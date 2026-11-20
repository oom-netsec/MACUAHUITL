package i18n

// Errores gRPC de los servicios de respaldos (backup.*), terminal (terminal.*) y visibilidad (visibility.*) (Fase 30c,
// bloque D). Los textos de sistema (rutas, errores del disco o de la red) viajan como argumento {error}.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"backup.err.dir_fuera":        e("backup.err.dir_fuera: {dir} no está dentro de la carpeta de salidas ni de la de un trabajo", "backup.err.dir_fuera: {dir} is not inside the outputs folder or a job's folder", "dir"),
		"backup.err.dir_sin_manifest": e("backup.err.dir_sin_manifest: {dir} no tiene un manifest.json legible: la corrida no terminó o no es una corrida", "backup.err.dir_sin_manifest: {dir} has no readable manifest.json: the run did not finish or is not a run", "dir"),
		"backup.err.keep":             e("la retención máxima es {max}", "the maximum retention is {max}", "max"),
		"backup.err.no_targets":       e("indica al menos un equipo", "specify at least one device"),
		"backup.err.rounds":           e("con intervalo indica cuántas rondas (2 o más)", "with an interval, specify how many rounds (2 or more)"),
		"backup.err.out_dir":          e("carpeta de salida: {error}", "output folder: {error}", "error"),
		"backup.err.diff_mismatch":    e("compara dos respaldos del mismo equipo y del mismo tipo", "compare two backups of the same device and the same type"),

		"terminal.err.out_dir":                  e("carpeta de salida: {error}", "output folder: {error}", "error"),
		"terminal.err.recording":                e("archivo de grabación: {error}", "recording file: {error}", "error"),
		"terminal.err.first_open":               e("el primer mensaje debe abrir la sesión", "the first message must open the session"),
		"terminal.err.no_address":               e("indica el equipo (dirección)", "specify the device (address)"),
		"terminal.err.port":                     e("puerto fuera de rango", "port out of range"),
		"terminal.err.vault_closed":             e("abre la bóveda: la terminal necesita las credenciales del equipo", "unlock the vault: the terminal needs the device credentials"),
		"terminal.err.max_sessions":             e("máximo {max} terminales abiertas", "at most {max} terminals open", "max"),
		"terminal.err.core_closing":             e("núcleo cerrándose", "core shutting down"),
		"terminal.err.shutting_down":            e("el núcleo se está cerrando", "the core is shutting down"),
		"terminal.err.client_gone":              e("cliente desconectado", "client disconnected"),
		"terminal.err.device_closed":            e("el equipo cerró la sesión", "the device closed the session"),
		"terminal.err.username":                 e("el usuario debe ser texto imprimible de hasta 128 bytes", "the username must be printable text of at most 128 bytes"),
		"terminal.err.username_with_credential": e("username solo va sin credencial guardada", "username only applies without a stored credential"),
		"terminal.err.auth_attempts":            e("el equipo rechazó la autenticación tras 3 intentos", "the device rejected authentication after 3 attempts"),
		"terminal.err.auth_timeout":             e("se agotó el tiempo para responder a la autenticación", "authentication timed out waiting for the answer"),
		"terminal.err.auth_no_method":           e("el equipo no ofrece password ni keyboard-interactive", "the device offers neither password nor keyboard-interactive"),
		"terminal.err.auth_answer":              e("respuesta de autenticación inválida: otro seq o distinto número de respuestas", "invalid authentication answer: wrong seq or number of answers"),
		"terminal.auth.login":                   e("usuario: ", "login as: "),
		"terminal.err.telnet_field":             e("con Telnet no van usuario, huellas ni host de la libreta", "username, host key fingerprints and a saved host do not apply to Telnet"),
		"terminal.err.protocol":                 e("protocolo de terminal desconocido", "unknown terminal protocol"),
		"terminal.telnet.cleartext_cred":        e("La credencial guardada también viaja en texto claro. El núcleo contesta el login con ella; lo que teclees antes se descarta.", "The stored credential also travels in clear text. The core answers the login with it; anything you type before that is discarded."),
		"terminal.telnet.manual_login":          e("El equipo no hizo la pregunta de login esperada a tiempo: sigue a mano.", "The device did not ask the expected login question in time: continue by hand."),
		"terminal.telnet.login_rejected":        e("El equipo rechazó la credencial guardada (no se reintenta): sigue a mano.", "The device rejected the stored credential (it is not retried): continue by hand."),
		"terminal.telnet.cleartext":             e("Telnet: todo viaja en texto claro, contraseña incluida, y no se verifica la identidad del equipo.", "Telnet: everything travels in clear text, password included, and the device identity is not verified."),
		"terminal.auth.denied":                  e("Acceso denegado", "Access denied"),
		"terminal.err.lost":                     e("conexión perdida: {error}", "connection lost: {error}", "error"),

		"terminal.err.host_and_address": e("con host_id no se indican dirección, puerto ni credencial: el host guardado ya los trae", "with host_id do not send address, port or credential: the saved host already has them"),
		"terminal.err.host_not_found":   e("el host guardado no existe", "the saved host does not exist"),
		"terminal.err.startup_changed":  e("la orden de inicio del host cambió desde que la viste: vuelve a abrir el host para revisarla", "the host's startup command changed since you saw it: reopen the host to review it"),
		"terminal.err.key_credential":   e("la credencial es de solo llave: solo sirve al abrir un host linux o windows guardado", "the credential is key-only: it only works when opening a saved linux or windows host"),

		"visibility.err.job_empty":   e("el trabajo aún no tiene salidas", "the job has no outputs yet"),
		"visibility.err.no_source":   e("indica un trabajo, una carpeta de salida o una captura", "specify a job, an output folder or a capture"),
		"visibility.err.relative":    e("la ruta {path:q} debe ser absoluta", "the path {path:q} must be absolute", "path"),
		"visibility.err.no_vault":    e("no hay bóveda; crea una y guarda la credencial", "there is no vault; create one and save the credential"),
		"visibility.err.no_cred":     e("falta la credencial", "the credential is missing"),
		"visibility.err.bad_snmp":    e("destino SNMP inválido", "invalid SNMP target"),
		"visibility.err.bad_port":    e("puerto inválido", "invalid port"),
		"visibility.err.bad_gnmi":    e("destino gNMI inválido", "invalid gNMI target"),
		"visibility.err.ca_relative": e("la ruta de la CA debe ser absoluta", "the CA path must be absolute"),
	})
}
