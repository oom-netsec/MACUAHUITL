package i18n

// Errores gRPC de los servicios de respaldos (backup.*), terminal (terminal.*) y visibilidad (visibility.*) (Fase 30c,
// bloque D). Los textos de sistema (rutas, errores del disco o de la red) viajan como argumento {error}.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"backup.err.keep":          e("la retención máxima es {max}", "the maximum retention is {max}", "max"),
		"backup.err.no_targets":    e("indica al menos un equipo", "specify at least one device"),
		"backup.err.rounds":        e("con intervalo indica cuántas rondas (2 o más)", "with an interval, specify how many rounds (2 or more)"),
		"backup.err.out_dir":       e("carpeta de salida: {error}", "output folder: {error}", "error"),
		"backup.err.diff_mismatch": e("compara dos respaldos del mismo equipo y del mismo tipo", "compare two backups of the same device and the same type"),

		"terminal.err.out_dir":       e("carpeta de salida: {error}", "output folder: {error}", "error"),
		"terminal.err.recording":     e("archivo de grabación: {error}", "recording file: {error}", "error"),
		"terminal.err.first_open":    e("el primer mensaje debe abrir la sesión", "the first message must open the session"),
		"terminal.err.no_address":    e("indica el equipo (dirección) y la credencial", "specify the device (address) and the credential"),
		"terminal.err.port":          e("puerto fuera de rango", "port out of range"),
		"terminal.err.vault_closed":  e("abre la bóveda: la terminal necesita las credenciales del equipo", "unlock the vault: the terminal needs the device credentials"),
		"terminal.err.max_sessions":  e("máximo {max} terminales abiertas", "at most {max} terminals open", "max"),
		"terminal.err.core_closing":  e("núcleo cerrándose", "core shutting down"),
		"terminal.err.shutting_down": e("el núcleo se está cerrando", "the core is shutting down"),
		"terminal.err.client_gone":   e("cliente desconectado", "client disconnected"),
		"terminal.err.device_closed": e("el equipo cerró la sesión", "the device closed the session"),
		"terminal.err.lost":          e("conexión perdida: {error}", "connection lost: {error}", "error"),

		"terminal.err.host_and_address":   e("con host_id no se indican dirección, puerto ni credencial: el host guardado ya los trae", "with host_id do not send address, port or credential: the saved host already has them"),
		"terminal.err.host_not_found":     e("el host guardado no existe", "the saved host does not exist"),
		"terminal.err.host_no_credential": e("el host guardado no tiene credencial: asígnale una para abrir el terminal", "the saved host has no credential: assign one to open the terminal"),
		"terminal.err.startup_changed":    e("la orden de inicio del host cambió desde que la viste: vuelve a abrir el host para revisarla", "the host's startup command changed since you saw it: reopen the host to review it"),
		"terminal.err.key_credential":     e("la credencial es de solo llave: solo sirve al abrir un host linux o windows guardado", "the credential is key-only: it only works when opening a saved linux or windows host"),

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
