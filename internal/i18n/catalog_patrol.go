package i18n

// Patrol y sus conexiones (Fase 30c, bloque D): validación del trabajo (patrol.field.*), detalle de los equipos y
// del Login Test (patrol.err.*, transport.*, platform.*) y errores del servicio de Patrol y de la bóveda
// (patrol.svc.*). Los textos de sistema (errores de red, del archivo) viajan como argumento {error} y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"patrol.field.no_targets":         e("sin equipos", "no devices"),
		"patrol.field.no_credential":      e("sin credencial por defecto", "no default credential"),
		"patrol.field.window":             e("debe estar entre 1 y 96, es {n}", "must be between 1 and 96, it is {n}", "n"),
		"patrol.field.no_commands":        e("sin playbooks ni comandos", "no playbooks or commands"),
		"patrol.field.no_playbook":        e("{id} no existe", "{id} does not exist", "id"),
		"patrol.field.cred_missing":       e("{id} no está en la bóveda", "{id} is not in the vault", "id"),
		"patrol.field.override_missing":   e("{id} (equipo {device}) no está en la bóveda", "{id} (device {device}) is not in the vault", "id", "device"),
		"patrol.field.schedule_exclusive": e("intervalo y cron son excluyentes", "interval and cron are mutually exclusive"),
		"patrol.field.cron":               e("cron: {error}", "cron: {error}", "error"),
		"patrol.field.until_past":         e("la fecha de fin ya pasó", "the end date has already passed"),
		"patrol.field.error":              e("{error}", "{error}", "error"),
		"patrol.writable.empty":           e("vacía", "empty"),
		"patrol.writable.not_dir":         e("no es una carpeta", "it is not a folder"),
		"patrol.writable.no_write":        e("sin permiso de escritura: {cause}", "no write permission: {cause}", "cause"),
		"patrol.err.credential":           e("patrol: credencial: {cause}", "patrol: credential: {cause}", "cause"),
		"patrol.err.window_ended":         e("terminó la ventana del trabajo con el equipo a medias", "the job window ended while the device was still being processed"),
		"patrol.err.audit":                e("auditoría: {error}", "audit: {error}", "error"),
		"patrol.err.playbook_platform":    e("patrol: el playbook {id} es para {platform} y el equipo es {detected}", "patrol: playbook {id} is for {platform} and the device is {detected}", "id", "platform", "detected"),
		"transport.err.not_authorized":    e("transport: destino no autorizado", "transport: destination not authorized"),
		"transport.err.auth":              e("transport: autenticación rechazada", "transport: authentication rejected"),
		"transport.err.known_hosts":       e("transport: known_hosts ilegible o dañado", "transport: known_hosts unreadable or damaged"),
		"transport.hostkey.unknown":       e("transport: llave de host desconocida de {host}: {fingerprint}", "transport: unknown host key from {host}: {fingerprint}", "host", "fingerprint"),
		"transport.hostkey.changed":       e("transport: llave de host cambiada de {host}: {fingerprint}", "transport: changed host key from {host}: {fingerprint}", "host", "fingerprint"),
		"transport.hostkey.known":         e("transport: llave de host conocida de {host}: {fingerprint}", "transport: known host key from {host}: {fingerprint}", "host", "fingerprint"),
		"platform.err.prompt_timeout":     e("platform: el equipo no mostró prompt a tiempo", "platform: the device did not show a prompt in time"),
		"platform.err.enable_failed":      e("platform: enable rechazado", "platform: enable rejected"),
		"platform.err.unknown":            e("platform: plataforma no reconocida", "platform: platform not recognized"),
		"platform.err.closed":             e("platform: el equipo cerró la sesión", "platform: the device closed the session"),
		"patrol.svc.no_vault_create":      e("no hay bóveda; créala primero", "there is no vault; create it first"),
		"patrol.svc.vault_exists":         e("la bóveda ya existe", "the vault already exists"),
		"patrol.svc.reserved_label":       e("la etiqueta {label:q} está reservada para el sistema", "the label {label:q} is reserved for the system", "label"),
		"patrol.svc.no_vault":             e("no hay bóveda", "there is no vault"),
		"patrol.svc.bad_kind":             e("tipo de trabajo {kind:q} no válido (patrol, adhoc, backup o change)", "job type {kind:q} is not valid (patrol, adhoc, backup or change)", "kind"),
		"patrol.svc.login_after_arm":      e("el trabajo está {state}; el Login Test solo aplica antes de armar", "the job is {state}; the Login Test only applies before arming", "state"),
		"patrol.svc.job_state":            e("el trabajo está {state}", "the job is {state}", "state"),
		"patrol.svc.no_devices_left":      e("no quedan equipos", "no devices are left"),
		"patrol.svc.login_failed":         e("Login Test falló; excluye o corrige: {failed}", "the Login Test failed; exclude or fix: {failed}", "failed"),
	})
}
