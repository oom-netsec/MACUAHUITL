package i18n

// Carpeta de salidas (Ajustes → Almacenamiento): el prefijo prefs.outputs.<motivo>: es estable y va en los dos idiomas.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"prefs.outputs.relativa":           e("prefs.outputs.relativa: la ruta debe ser absoluta: {dir:q}", "prefs.outputs.relativa: the path must be absolute: {dir:q}", "dir"),
		"prefs.outputs.punto_punto":        e("prefs.outputs.punto_punto: la ruta no puede llevar \"..\": {dir:q}", "prefs.outputs.punto_punto: the path cannot contain \"..\": {dir:q}", "dir"),
		"prefs.outputs.no_existe":          e("prefs.outputs.no_existe: la carpeta no existe: {dir} (créala con permisos 0700)", "prefs.outputs.no_existe: the folder does not exist: {dir} (create it with 0700 permissions)", "dir"),
		"prefs.outputs.ilegible":           e("prefs.outputs.ilegible: no se pudo leer la carpeta {dir}: {err}", "prefs.outputs.ilegible: could not read the folder {dir}: {err}", "dir", "err"),
		"prefs.outputs.ilegible_ruta":      e("prefs.outputs.ilegible: no se pudo leer {dir}: {err}", "prefs.outputs.ilegible: could not read {dir}: {err}", "dir", "err"),
		"prefs.outputs.no_directorio":      e("prefs.outputs.no_directorio: {dir} no es una carpeta", "prefs.outputs.no_directorio: {dir} is not a folder", "dir"),
		"prefs.outputs.reservada":          e("prefs.outputs.reservada: {dir} no puede ser la carpeta de salidas", "prefs.outputs.reservada: {dir} cannot be the outputs folder", "dir"),
		"prefs.outputs.reservada_dentro":   e("prefs.outputs.reservada: {dir} está dentro de una carpeta reservada ({res})", "prefs.outputs.reservada: {dir} is inside a reserved folder ({res})", "dir", "res"),
		"prefs.outputs.reservada_contiene": e("prefs.outputs.reservada: {dir} contiene la carpeta reservada {res}", "prefs.outputs.reservada: {dir} contains the reserved folder {res}", "dir", "res"),
		"prefs.outputs.otro_dueno":         e("prefs.outputs.otro_dueno: la carpeta {dir} no es del usuario que corre el núcleo", "prefs.outputs.otro_dueno: the folder {dir} does not belong to the user running the core", "dir"),
		"prefs.outputs.permisos":           e("prefs.outputs.permisos: la carpeta {dir} tiene modo {mode} y debe ser 0700", "prefs.outputs.permisos: the folder {dir} has mode {mode} and must be 0700", "dir", "mode"),
		"prefs.outputs.permisos_orden":     e("prefs.outputs.permisos: la carpeta {dir} tiene modo {mode} y debe ser 0700; corrígelo con: chmod 700 {dir}", "prefs.outputs.permisos: the folder {dir} has mode {mode} and must be 0700; fix it with: chmod 700 {dir}", "dir", "mode"),
		"prefs.outputs.ancestro_inseguro":  e("prefs.outputs.ancestro_inseguro: {dir} cuelga de {anc}, que otros usuarios pueden escribir (modo {mode}, dueño uid {uid}): otro usuario podría reemplazar la ruta; elige una carpeta bajo tu carpeta personal", "prefs.outputs.ancestro_inseguro: {dir} hangs from {anc}, which other users can write to (mode {mode}, owner uid {uid}): another user could replace the path; choose a folder under your home folder", "dir", "anc", "mode", "uid"),
		"prefs.outputs.no_escribible":      e("prefs.outputs.no_escribible: no se puede escribir en {dir}: {err}", "prefs.outputs.no_escribible: cannot write to {dir}: {err}", "dir", "err"),
		"prefs.outputs.issue":              e("la carpeta de salidas guardada ({dir}) ya no es válida y se usa la de fábrica: {reason}", "the saved outputs folder ({dir}) is no longer valid and the factory one is used: {reason}", "dir", "reason"),
		"prefs.outputs.note":               e("El cambio aplica a lo que empiece después: los trabajos y escuchas en curso conservan la carpeta con que arrancaron. Los datos de la carpeta anterior no se mueven.", "The change applies to what starts afterwards: jobs and listeners already running keep the folder they started with. Data in the previous folder is not moved."),
	})
}
