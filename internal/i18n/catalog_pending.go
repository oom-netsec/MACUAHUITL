package i18n

// Reversa asistida de lo que una ejecución dejó cambiado (assist/pending.go, service/assist/pending.go, mctl ports rollback).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"assist.pending.no_state":          e("no se guardó el estado en que {device} quedó: sin él no se puede comprobar que nadie lo tocó; revierte a mano", "the state {device} was left in was not saved: without it there is no way to check that nobody touched it; revert by hand", "device"),
		"assist.pending.not_verifiable":    e("el plan de {device} no guardó un estado de antes que permita verificar la vuelta; revierte a mano", "the plan of {device} did not keep a prior state that allows verifying the return; revert by hand", "device"),
		"assist.pending.write_memory":      e("la startup-config puede conservar el cambio (la ejecución original pedía write memory); la reversa no hace write memory", "the startup-config may keep the change (the original run asked for write memory); the rollback does not do write memory"),
		"assist.svc.reversa_en_curso":      e("la ejecución {id} sigue viva en este núcleo: su reversa no está disponible hasta que termine", "run {id} is still alive in this core: its rollback is not available until it ends", "id"),
		"mctl.ports.rollback_write_memory": e("  AVISO: la startup-config puede conservar el cambio; la reversa no hace write memory.", "  NOTE: the startup-config may keep the change; the rollback does not do write memory."),
		"mctl.ports.rollback_unreadable":   e("Reversa de la ejecución {run}: ilegible (descártala con: mctl ports rollback discard {run})", "Rollback of run {run}: unreadable (discard it with: mctl ports rollback discard {run})", "run"),
		"mctl.ports.rollback_discarded":    e("Reversa {run} descartada.", "Rollback {run} discarded.", "run"),
		"assist.post.not_restored":         e("{command} no volvió a su estado de antes", "{command} did not return to its previous state", "command"),
		"assist.svc.reversa_no_existe":     e("no hay una reversa pendiente de la ejecución {id}", "there is no pending rollback for run {id}", "id"),
		"assist.svc.reversa_vieja":         e("la reversa pendiente terminó hace {age}: el equipo pudo cambiar desde entonces; repite con la confirmación de antigüedad (--accept-age)", "the pending rollback ended {age} ago: the device may have changed since; repeat with the age confirmation (--accept-age)", "age"),
		"assist.svc.reversa_ilegible":      e("la reversa pendiente {id} no se pudo leer: {cause}", "the pending rollback {id} could not be read: {cause}", "id", "cause"),
		"mctl.flag.accept-age":             e("aceptar una reversa de más de 24 h", "accept a rollback older than 24 h"),
		"mctl.run.warn_pending":            e("\nATENCIÓN: {devices} quedó cambiado. La reversa quedó guardada: mctl ports rollback {run}", "\nATTENTION: {devices} was left changed. The rollback was saved: mctl ports rollback {run}", "devices", "run"),
		"mctl.ports.no_rollbacks":          e("No hay reversas pendientes.", "There are no pending rollbacks."),
		"mctl.ports.rollback_header":       e("Reversa de la ejecución {run} ({kind}), terminó hace {age}:", "Rollback of run {run} ({kind}), ended {age} ago:", "run", "kind", "age"),
		"mctl.ports.rollback_started":      e("Ejecución de reversa {run}: confirma cada paso.", "Rollback run {run}: confirm each step.", "run"),
	})
}
