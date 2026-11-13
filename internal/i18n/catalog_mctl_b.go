package i18n

// Fase 30e: mensajes propios de mctl (patrol, pack, backup, restore, field, diag, adhoc, acl, analysis, audit, calc,
// change, cleaner, credrotate, forensic y prefs). La ayuda y los «uso: mctl …» se quedan en español a propósito.
func init() {
	e := func(es, en string) entry { return entry{Es: es, En: en, Args: tplArgs(es, en)} }
	add(map[string]entry{
		// Compartidos
		"mctl.backup.port_invalid":   e("puerto inválido en {value:q}", "invalid port in {value:q}"),
		"mctl.backup.write_out":      e("no se escribe la salida (¿ya existe?): {cause}", "the output is not written (does it already exist?): {cause}"),
		"mctl.backup.written":        e("escrito {path}", "written {path}"),
		"mctl.restore.assist_active": e("MODO ASISTIDO ACTIVO. Ejecución {run}: cada paso que cambia la red pide confirmación.", "ASSISTED MODE ACTIVE. Run {run}: every step that changes the network asks for confirmation."),
		"mctl.restore.plan_only":     e("Solo se mostró el plan: no se cambió nada. Para aplicarlo agrega --asistido.", "Only the plan was shown: nothing was changed. To apply it add --asistido."),

		// patrol
		"mctl.patrol.param_form":    e("--param {param:q}: use nombre=valor", "--param {param:q}: use name=value"),
		"mctl.patrol.param_dup":     e("--param {name:q} repetido", "--param {name:q} given more than once"),
		"mctl.patrol.login_fail":    e("{addr}  FALLA  {step}  {detail}", "{addr}  FAILED  {step}  {detail}"),
		"mctl.patrol.login_fp":      e("  huella={fp} (confírmala con: mctl job arm --accept {fp} {id})", "  fingerprint={fp} (confirm it with: mctl job arm --accept {fp} {id})"),
		"mctl.patrol.login_failed":  e("{n} equipos no pasaron el Login Test", "{n} {n|device|devices} failed the Login Test"),
		"mctl.patrol.arm_need_id":   e("job arm necesita un ID", "job arm needs an ID"),
		"mctl.patrol.armed":         e("armado; la llave de la bóveda queda en memoria hasta {until}", "armed; the vault key stays in memory until {until}"),
		"mctl.patrol.armed_warn":    e("aviso: la laptop podría suspenderse; faltan bloqueos: {list}", "warning: the laptop could suspend; missing inhibitors: {list}"),
		"mctl.patrol.playbook_line": e("{id}  {name}  {n} comandos", "{id}  {name}  {n} {n|command|commands}"),
		"mctl.patrol.playbook_data": e("  datos: {list}", "  data: {list}"),
		"mctl.patrol.watch_phase":   e("{t}  fase  {kind}  ronda={round}  {detail}", "{t}  phase  {kind}  round={round}  {detail}"),
		"mctl.patrol.watch_warning": e("{t}  aviso  {code}", "{t}  warning  {code}"),
		"mctl.patrol.watch_job":     e("{t}  trabajo  {state}", "{t}  job  {state}"),

		// pack
		"mctl.pack.official":  e("oficial", "official"),
		"mctl.pack.third":     e("terceros", "third-party"),
		"mctl.pack.hidden_n":  e("  ({n} ocultos)", "  ({n} hidden)"),
		"mctl.pack.shadowed":  e("  (tapados por los tuyos: {list})", "  (shadowed by your own: {list})"),
		"mctl.pack.installed": e("instalado", "installed"),
		"mctl.pack.updated":   e("actualizado (antes {version})", "updated (was {version})"),
		"mctl.pack.replaces":  e("reemplazaría la versión {version}", "would replace version {version}"),
		"mctl.pack.hidden":    e("ocultos: {list}", "hidden: {list}"),
		"mctl.pack.none":      e("no hay paquetes instalados", "no packs installed"),
		"mctl.pack.show": e("id: {id}\nversión: {version}\norigen: {origin}\nnúcleo mínimo: {min_core}\nnombre: {name}\ndescripción: {description}\nplataformas: {platforms}\nautor: {author}\nlicencia: {license}\nplaybooks: {playbooks}\nscripts: {scripts}\n\n{readme}",
			"id: {id}\nversion: {version}\norigin: {origin}\nminimum core: {min_core}\nname: {name}\ndescription: {description}\nplatforms: {platforms}\nauthor: {author}\nlicense: {license}\nplaybooks: {playbooks}\nscripts: {scripts}\n\n{readme}"),
		"mctl.pack.removed": e("quitado: {id} ({n} favoritos quitados)", "removed: {id} ({n} favorites removed)"),

		// backup
		"mctl.backup.unarmed":        e("trabajo {job} creado sin armar: {detail}\nrevisa con: mctl job logintest {job}\ny repite con --accept HUELLA", "job {job} created but not armed: {detail}\ncheck with: mctl job logintest {job}\nand repeat with --accept FINGERPRINT"),
		"mctl.backup.unarmed_err":    e("respaldo sin armar", "backup not armed"),
		"mctl.backup.job_error":      e("el trabajo {job} terminó con error: {error}", "job {job} finished with an error: {error}"),
		"mctl.backup.timeout":        e("sin resultado tras {timeout}; guárdalo después con: mctl backup collect {job}", "no result after {timeout}; save it later with: mctl backup collect {job}"),
		"mctl.backup.scheduled":      e("programado: trabajo {job}, {rounds} rondas cada {every}; el núcleo guarda cada una al terminar (mctl backup list)", "scheduled: job {job}, {rounds} rounds every {every}; the core saves each one when it finishes (mctl backup list)"),
		"mctl.backup.still_running":  e("el trabajo sigue en estado {state}; vuelve a ejecutarlo al terminar", "the job is still in state {state}; run it again when it finishes"),
		"mctl.backup.bad_id":         e("identificador {id:q} inválido", "invalid identifier {id:q}"),
		"mctl.backup.new_missing":    e("el respaldo nuevo no apareció en la lista", "the new backup did not appear in the list"),
		"mctl.backup.masked_warning": e("aviso: este respaldo se tomó con secretos enmascarados; no sirve para recuperar contraseñas ni llaves", "warning: this backup was taken with masked secrets; it cannot recover passwords or keys"),

		// restore
		"mctl.restore.max_lines":       e("--max-lines va de 1 a 1000", "--max-lines must be between 1 and 1000"),
		"mctl.restore.rejected":        e("PLAN RECHAZADO: {reason}", "PLAN REJECTED: {reason}"),
		"mctl.restore.rejected_err":    e("el plan se rechazó: nada se cambió", "the plan was rejected: nothing was changed"),
		"mctl.restore.refused":         e("No se restaura (hazlo a mano):", "Not restored (do it by hand):"),
		"mctl.restore.refused_partial": e("No se restaura (plan parcial; hazlo a mano):", "Not restored (partial plan; do it by hand):"),

		// field
		"mctl.field.console_help":  e("Ctrl-] q sale · Ctrl-] b envía BREAK · Ctrl-] Ctrl-] envía Ctrl-] · Ctrl-] ? ayuda", "Ctrl-] q quits · Ctrl-] b sends BREAK · Ctrl-] Ctrl-] sends Ctrl-] · Ctrl-] ? help"),
		"mctl.field.connected":     e("conectado a {opened}; grabando en {path}", "connected to {opened}; recording to {path}"),
		"mctl.field.break_sent":    e("BREAK enviado", "BREAK sent"),
		"mctl.field.console_close": e("consola cerrada", "console closed"),
		"mctl.field.no_adapters":   e("no hay adaptadores USB-serie conectados (/dev/ttyUSB*, /dev/ttyACM*)", "no USB-serial adapters connected (/dev/ttyUSB*, /dev/ttyACM*)"),
		"mctl.field.many_ports":    e("hay varios puertos: indica cuál, p. ej. mctl console /dev/ttyUSB0", "there are several ports: say which one, e.g. mctl console /dev/ttyUSB0"),
		"mctl.field.serving":       e("sirviendo en {listen}/{proto}", "serving on {listen}/{proto}"),
		"mctl.field.hash_mismatch": e("el resumen no coincide con el publicado: no instales esta imagen", "the digest does not match the published one: do not install this image"),

		// diag
		"mctl.diag.opt_bad":   e("opción {opt:q}: usa clave=valor", "option {opt:q}: use key=value"),
		"mctl.diag.saved":     e("guardado en {path} (código de salida {code})", "saved to {path} (exit code {code})"),
		"mctl.diag.exit_code": e("{tool} terminó con código {code}", "{tool} exited with code {code}"),
		"mctl.diag.if_up":     e("arriba", "up"),
		"mctl.diag.if_down":   e("abajo", "down"),

		// adhoc
		"mctl.adhoc.unarmed":     e("trabajo {job} creado sin armar: {detail}\nrevisa con: mctl job logintest {job}\ny repite con --accept HUELLA (o arma con mctl job arm)", "job {job} created but not armed: {detail}\ncheck with: mctl job logintest {job}\nand repeat with --accept FINGERPRINT (or arm with mctl job arm)"),
		"mctl.adhoc.unarmed_err": e("lote sin armar", "batch not armed"),
		"mctl.adhoc.no_results":  e("el trabajo {job} terminó {state} sin resultados", "job {job} ended {state} with no results"),
		"mctl.adhoc.timeout":     e("sin resultado tras {timeout}; consúltalo después con el trabajo {job}", "no result after {timeout}; check it later with job {job}"),

		// acl
		"mctl.acl.missing_flags": e("faltan --vendor/--from y -f", "--vendor/--from and -f are required"),
		"mctl.acl.shadowed":      e("sombreada", "shadowed"),
		"mctl.acl.redundant":     e("redundante", "redundant"),
		"mctl.acl.impossible":    e("imposible", "impossible"),
		"mctl.acl.finding":       e("regla {n}: {kind}: {detail}", "rule {n}: {kind}: {detail}"),
		"mctl.acl.findings":      e("{n} hallazgos en {name}", "{n} {n|finding|findings} in {name}"),
		"mctl.acl.clean":         e("{name}: {n} reglas, sin hallazgos", "{name}: {n} {n|rule|rules}, no findings"),

		// analysis
		"mctl.analysis.around": e("--around: usa RFC 3339, p. ej. 2026-11-04T10:09:18Z", "--around: use RFC 3339, e.g. 2026-11-04T10:09:18Z"),

		// audit
		"mctl.audit.broken": e("la cadena de auditoría está rota en el registro {seq}", "the audit chain is broken at record {seq}"),
		"mctl.audit.intact": e("cadena íntegra; cabeza {head}", "chain intact; head {head}"),

		// calc
		"mctl.calc.need_invalid": e("necesidad {need:q} inválida: usa NOMBRE=HOSTS o HOSTS", "invalid requirement {need:q}: use NAME=HOSTS or HOSTS"),
		"mctl.calc.mtu_invalid":  e("MTU {mtu} inválida", "invalid MTU {mtu}"),
		"mctl.calc.mss_invalid":  e("MSS {mss} inválido", "invalid MSS {mss}"),
		"mctl.calc.negative":     e("conectores y empalmes no pueden ser negativos", "connectors and splices cannot be negative"),
		"mctl.calc.route_num":    e("ruta {route:q}: {key}={value:q} no es un número", "route {route:q}: {key}={value:q} is not a number"),

		// change
		"mctl.change.need_id":    e("change {name} necesita el ID del cambio", "change {name} needs the change ID"),
		"mctl.change.unarmed":    e("trabajo {job} creado sin armar: {detail}\nrevisa con: mctl job logintest {job}\ny repite con: mctl change {name} --accept HUELLA {id} (o arma con mctl job arm)", "job {job} created but not armed: {detail}\ncheck with: mctl job logintest {job}\nand repeat with: mctl change {name} --accept FINGERPRINT {id} (or arm with mctl job arm)"),
		"mctl.change.unarmed_er": e("captura {name} sin armar", "capture {name} not armed"),
		"mctl.change.capturing":  e("captura {name} en trabajo {job}; síguela con: mctl job watch {job}", "capture {name} in job {job}; follow it with: mctl job watch {job}"),
		"mctl.change.regression": e("{n} equipos con regresión", "{n} {n|device|devices} with regression"),

		// cleaner
		"mctl.cleaner.same_file": e("la salida no puede ser el archivo de entrada: la limpieza no sobrescribe el original", "the output cannot be the input file: cleaning does not overwrite the original"),

		// credrotate
		"mctl.credrotate.generate": e("--generate exige --update-cred: un secreto generado solo se recupera desde la bóveda", "--generate requires --update-cred: a generated secret can only be recovered from the vault"),
		"mctl.credrotate.prompt":   e("Secreto nuevo de {user}: ", "New secret for {user}: "),
		"mctl.credrotate.note_1":   e("Los secretos (el nuevo y el hash previo) no se muestran nunca; la reversa los restaura desde el núcleo.", "The secrets (the new one and the previous hash) are never shown; the rollback restores them from the core."),
		"mctl.credrotate.note_2":   e("write memory es obligatorio: sin él el equipo volvería al hash anterior al reiniciar. La bóveda se actualiza solo después de que", "write memory is mandatory: without it the device would return to the previous hash on reload. The vault is updated only after"),
		"mctl.credrotate.note_3":   e("write memory salga con [OK]; la credencial anterior se conserva como \"<etiqueta> (anterior)\" hasta que la borres a mano.", "write memory exits with [OK]; the previous credential is kept as \"<label> (previous)\" until you delete it by hand."),
		"mctl.credrotate.note_4":   e("Si rechazas write memory, la ejecución no termina: se propone la reversa.", "If you reject write memory, the run does not finish: the rollback is proposed."),

		// forensic
		"mctl.forensic.stdin_max": e("la entrada excede {n} MiB", "the input exceeds {n} MiB"),
		"mctl.forensic.no_source": e("elige una fuente: ARCHIVO (o - para la entrada estándar), --capture o --job TRABAJO", "choose a source: FILE (or - for standard input), --capture or --job JOB"),

		// prefs
		"mctl.prefs.default": e("de fábrica", "factory default"),
		"mctl.prefs.show": e("carpeta de salidas: {dir}{suffix}\nrotar_mb: {mb}\nrotar_min: {min}\nmax_archivos: {max}\nformato: {format}",
			"outputs folder: {dir}{suffix}\nrotate_mb: {mb}\nrotate_min: {min}\nmax_files: {max}\nformat: {format}"),
	})
}
