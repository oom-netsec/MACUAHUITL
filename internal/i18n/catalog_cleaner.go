package i18n

// Limpieza de configuración y deriva entre rondas: texto de los informes, motivos de las huérfanas y avisos.
// Las líneas de configuración, nombres de objetos y rutas viajan como argumentos y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"cleaner.err.empty": e("falta la configuración", "the configuration is missing"),

		"cleaner.why.missing": e("{kind} {key} no existe ({via})", "{kind} {key} does not exist ({via})", "kind", "key", "via"),
		"cleaner.why.unused":  e("class-map {name} sin uso (ningún policy-map la usa)", "class-map {name} is unused (no policy-map uses it)", "name"),
		"cleaner.change.sort": e("{n} bloques {kind:q} reordenados", "{n} {kind:q} blocks reordered", "n", "kind"),
		"cleaner.mark":        e("HUERFANA", "ORPHAN"),

		"cleaner.text.blank":   e("líneas vacías quitadas", "empty lines removed"),
		"cleaner.text.bang":    e("separadores ! repetidos quitados", "repeated ! separators removed"),
		"cleaner.text.trail":   e("líneas con espacio final recortado", "lines with trailing space trimmed"),
		"cleaner.text.group":   e("{n} {label} (líneas de origen: {ranges})", "{n} {label} (source lines: {ranges})", "n", "label", "ranges"),
		"cleaner.text.sort":    e("orden: {text} (desde la línea {line})", "order: {text} (from line {line})", "text", "line"),
		"cleaner.text.none":    e("Sin cambios de formato.", "No formatting changes."),
		"cleaner.text.orphans": e("{n} HUÉRFANAS (marcadas con un comentario ! en la salida)", "{n} ORPHANS (marked with a ! comment in the output)", "n"),
		"cleaner.text.orphan":  e("línea {line}: {text} — {why}", "line {line}: {text} — {why}", "line", "text", "why"),
		"cleaner.text.footer":  e("Las huérfanas solo se marcan: la limpieza nunca las quita.", "Orphans are only marked: the cleanup never removes them."),

		"drift.masked_notice": e("los cambios en secretos no son visibles porque el trabajo enmascara secretos", "changes to secrets are not visible because the job masks secrets"),
		"drift.err.no_pair":   e("ningún equipo tiene dos rondas con show running-config; usa un playbook que lo recolecte y espera la segunda ronda", "no device has two rounds with show running-config; use a playbook that collects it and wait for the second round"),
		"drift.warn.no_pair":  e("{dev}: sin dos rondas con running-config (tiene {have})", "{dev}: no two rounds with running-config (has {have})", "dev", "have"),
		"drift.text.warning":  e("AVISO: {message}", "WARNING: {message}", "message"),
		"drift.text.none":     e("{device}: sin deriva (ronda {to} contra {from})", "{device}: no drift (round {to} against {from})", "device", "to", "from"),
		"drift.text.changes":  e("{device}: {n} cambios ({added} agregadas, {removed} quitadas), ronda {to} contra {from}", "{device}: {n} {n|change|changes} ({added} added, {removed} removed), round {to} against {from}", "device", "n", "added", "removed", "to", "from"),
		"drift.text.ignored":  e("ignoradas por volátiles: {list}", "ignored as volatile: {list}", "list"),
		"drift.text.warn":     e("Aviso: {message}", "Warning: {message}", "message"),
		"drift.text.total":    e("{n} de {total} equipos con deriva", "{n} of {total} devices with drift", "n", "total"),
	})
}
