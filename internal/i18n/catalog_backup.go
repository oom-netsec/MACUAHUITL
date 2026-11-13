package i18n

// Respaldos de configuración (internal/backup y internal/service/backup): errores del almacén, informe de
// CollectBackups, lista y comparación. Equipos, identificadores, rutas y líneas de configuración son datos.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"backup.store.bad_device":   e("backup: nombre de equipo {device:q} inválido", "backup: invalid device name {device:q}", "device"),
		"backup.store.not_dir":      e("backup: {dir} no es una carpeta de verdad (¿enlace simbólico?)", "backup: {dir} is not a real folder (a symbolic link?)", "dir"),
		"backup.store.bad_kind":     e("backup: tipo {kind:q} inválido", "backup: invalid type {kind:q}", "kind"),
		"backup.store.not_regular":  e("backup: {path} no es un archivo regular", "backup: {path} is not a regular file", "path"),
		"backup.store.bad_meta":     e("ficha no válida", "invalid metadata file"),
		"backup.store.bad_id":       e("backup: identificador {id:q} inválido (equipo/AAAAMMDDTHHMMSSZ-running|startup)", "backup: invalid identifier {id:q} (device/YYYYMMDDTHHMMSSZ-running|startup)", "id"),
		"backup.store.not_found":    e("backup: no existe {id}", "backup: {id} does not exist", "id"),
		"backup.store.min_keep":     e("backup: la retención mínima es 1", "backup: the minimum retention is 1"),
		"backup.rep.saved":          e("{saved} respaldo(s) guardado(s), {skipped} ya existían", "{saved} backup(s) saved, {skipped} already existed", "saved", "skipped"),
		"backup.rep.pruned":         e(", {n} borrado(s) por retención", ", {n} deleted by retention", "n"),
		"backup.rep.warning":        e("Aviso: {w}", "Warning: {w}", "w"),
		"backup.rep.notice":         e("AVISO: {w}", "WARNING: {w}", "w"),
		"backup.warn.no_startup":    e("{device}: el equipo no devolvió startup-config", "{device}: the device did not return startup-config", "device"),
		"backup.warn.outside":       e("{device}: sección de {cmd} fuera de la ventana del trabajo ({at}): se descartó", "{device}: section of {cmd} outside the job window ({at}): discarded", "device", "cmd", "at"),
		"backup.warn.unsigned":      e("respaldos guardados sin firma: la bóveda está cerrada y la ficha no se puede firmar; se pueden ver y comparar, pero no restaurar", "backups saved without a signature: the vault is locked and the record cannot be signed; they can be viewed and compared, but not restored"),
		"backup.warn.dup_section":   e("{device}: más de una sección de {cmd} en la ronda {round}: no se sabe cuál es la real, se descartaron todas", "{device}: more than one section of {cmd} in round {round}: it is not known which one is real, all were discarded", "device", "cmd", "round"),
		"backup.warn.device_cause":  e("{device}: {cause}", "{device}: {cause}", "device", "cause"),
		"backup.warn.prune":         e("{device}: retención: {cause}", "{device}: retention: {cause}", "device", "cause"),
		"backup.list.masked":        e(" enmascarado", " masked"),
		"backup.list.none":          e("sin respaldos", "no backups"),
		"backup.list.masked_notice": e("los respaldos marcados «enmascarado» se tomaron con secretos enmascarados: sirven para ver y comparar, no para recuperar contraseñas ni llaves", "the backups marked \"masked\" were taken with masked secrets: they are good for viewing and comparing, not for recovering passwords or keys"),
		"backup.diff.head":          e("{device}: {to} contra {from}", "{device}: {to} against {from}", "device", "to", "from"),
		"backup.diff.none":          e("sin diferencias", "no differences"),
		"backup.diff.count":         e("{n} cambios ({added} agregadas, {removed} quitadas)", "{n} changes ({added} added, {removed} removed)", "n", "added", "removed"),
		"backup.diff.ignored":       e("  ignoradas por volátiles: {list}", "  ignored as volatile: {list}", "list"),
	})
}
