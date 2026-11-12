package i18n

// Métricas de un trabajo de Patrol (Fase 30c, bloque D): avisos (metrics.warn.*, metrics.ports.*), errores
// (metrics.err.*) y errores del servicio (metrics.svc.*). Los comandos de IOS, equipos e interfaces son datos.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"metrics.warn.missing_cmd":    e("falta el comando {cmd}: el playbook no lo recolectó", "missing command {cmd_en}: the playbook did not collect it", "cmd", "cmd_en"),
		"metrics.warn.unreadable":     e("no se pudo leer {cmd} en {n} {n|ronda|rondas}", "{cmd} could not be read in {n} {n|round|rounds}", "cmd", "n"),
		"metrics.warn.top_ifaces":     e("se muestran las {shown} interfaces con más utilización de {total}", "showing the {shown} most utilized interfaces out of {total}", "shown", "total"),
		"metrics.warn.no_device":      e("el trabajo no tiene datos del equipo {device:q}", "the job has no data for device {device:q}", "device"),
		"metrics.warn.no_iface":       e("la interfaz {iface} no aparece en los datos de los equipos", "interface {iface} does not appear in the devices' data", "iface"),
		"metrics.warn.file_big":       e("no se leyó {file}: supera {size}", "{file} was not read: it exceeds {size}", "file", "size"),
		"metrics.warn.total_cap":      e("el equipo pasa del tope de {size} de texto: se dejó de leer en {file}", "the device exceeds the {size} text limit: reading stopped at {file}", "size", "file"),
		"metrics.warn.read_failed":    e("no se pudo leer {file}: {error}", "{file} could not be read: {error}", "file", "error"),
		"metrics.warn.read_too_big":   e("no se pudo leer {file}: el archivo creció más allá del tope mientras se leía", "{file} could not be read: the file grew past the limit while it was being read", "file"),
		"metrics.ports.no_status":     e("falta el comando {cmd}: sin él no hay puertos que mostrar", "missing command {cmd}: without it there are no ports to show", "cmd"),
		"metrics.ports.no_trunk":      e("falta el comando {cmd}: «trunk» se deduce de la columna VLAN y no se conoce la VLAN nativa", "missing command {cmd}: \"trunk\" is inferred from the VLAN column and the native VLAN is unknown", "cmd"),
		"metrics.ports.no_channels":   e("falta el comando {cmd}: no se sabe qué puertos son miembros de un canal", "missing command {cmd}: it is not known which ports are members of a channel", "cmd"),
		"metrics.ports.unread_status": e("no se pudo leer {cmd}: no trae la tabla de puertos", "{cmd} could not be read: it has no port table", "cmd"),
		"metrics.ports.unread":        e("no se pudo leer {cmd}", "{cmd} could not be read", "cmd"),
		"metrics.err.no_device":       e("metrics: el trabajo no tiene datos del equipo {device:q}", "metrics: the job has no data for device {device:q}", "device"),
		"metrics.err.no_outputs":      e("metrics: el trabajo no tiene salidas de equipos", "metrics: the job has no device outputs"),
		"metrics.err.many":            e("metrics: el trabajo tiene {n} equipos ({names}): indica uno", "metrics: the job has {n} devices ({names}): specify one", "n", "names"),
		"metrics.err.no_host":         e("metrics: el trabajo no tiene salidas del equipo {host}", "metrics: the job has no outputs for device {host}", "host"),
		"metrics.err.too_big":         e("el archivo creció más allá del tope mientras se leía", "the file grew past the limit while it was being read"),

		"metrics.svc.platform":     e("plataforma {platform:q} no soportada: la vista de frente lee IOS e IOS-XE", "platform {platform:q} is not supported: the front view reads IOS and IOS-XE", "platform"),
		"metrics.svc.job_empty":    e("el trabajo aún no tiene salidas", "the job has no outputs yet"),
		"metrics.svc.no_source":    e("indica un trabajo o una carpeta de salida", "specify a job or an output folder"),
		"metrics.svc.relative":     e("la ruta {path:q} debe ser absoluta", "the path {path:q} must be absolute", "path"),
		"metrics.svc.bad_limits":   e("topes inválidos", "invalid limits"),
		"metrics.svc.live_target":  e("indica un trabajo, o el equipo y su credencial para consultarlo en vivo", "specify a job, or the device and its credential to query it live"),
		"metrics.svc.live_cred":    e("la consulta en vivo necesita una credencial de la bóveda", "the live query needs a vault credential"),
		"metrics.svc.vault_locked": e("abre la bóveda: la consulta necesita la credencial", "unlock the vault: the query needs the credential"),
	})
}
