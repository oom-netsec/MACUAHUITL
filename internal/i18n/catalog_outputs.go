package i18n

import (
	"slices"
	"strings"
)

// Carpeta de salidas (Ajustes → Almacenamiento): el motivo prefs.outputs.<motivo> es estable y viaja en ErrorInfo.Reason, no en el texto (43e-9).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"prefs.outputs.relativa":              e("la ruta debe ser absoluta: {dir:q}", "the path must be absolute: {dir:q}", "dir"),
		"prefs.outputs.sin_unidad":            e("en Windows la carpeta debe empezar con una letra de unidad (C:\\...); no se aceptan rutas de red (\\\\servidor\\recurso) ni de dispositivo: {dir:q}", "on Windows the folder must start with a drive letter (C:\\...); network (\\\\server\\share) and device paths are not accepted: {dir:q}", "dir"),
		"prefs.outputs.punto_punto":           e("la ruta no puede llevar \"..\": {dir:q}", "the path cannot contain \"..\": {dir:q}", "dir"),
		"prefs.outputs.no_existe":             e("la carpeta no existe: {dir} (créala con permisos 0700)", "the folder does not exist: {dir} (create it with 0700 permissions)", "dir"),
		"prefs.outputs.no_existe_win":         withReason(e("la carpeta no existe: {dir} (créala primero)", "the folder does not exist: {dir} (create it first)", "dir"), "prefs.outputs.no_existe"),
		"prefs.outputs.ilegible":              e("no se pudo leer la carpeta {dir}: {err}", "could not read the folder {dir}: {err}", "dir", "err"),
		"prefs.outputs.ilegible_ruta":         withReason(e("no se pudo leer {dir}: {err}", "could not read {dir}: {err}", "dir", "err"), "prefs.outputs.ilegible"),
		"prefs.outputs.no_directorio":         e("{dir} no es una carpeta", "{dir} is not a folder", "dir"),
		"prefs.outputs.reservada":             e("{dir} no puede ser la carpeta de salidas", "{dir} cannot be the outputs folder", "dir"),
		"prefs.outputs.reservada_dentro":      withReason(e("{dir} está dentro de una carpeta reservada ({res})", "{dir} is inside a reserved folder ({res})", "dir", "res"), "prefs.outputs.reservada"),
		"prefs.outputs.reservada_contiene":    withReason(e("{dir} contiene la carpeta reservada {res}", "{dir} contains the reserved folder {res}", "dir", "res"), "prefs.outputs.reservada"),
		"prefs.outputs.otro_dueno":            e("la carpeta {dir} no es del usuario que corre el núcleo", "the folder {dir} does not belong to the user running the core", "dir"),
		"prefs.outputs.permisos":              e("la carpeta {dir} tiene modo {mode} y debe ser 0700", "the folder {dir} has mode {mode} and must be 0700", "dir", "mode"),
		"prefs.outputs.permisos_orden":        withReason(e("la carpeta {dir} tiene modo {mode} y debe ser 0700; corrígelo con: chmod 700 {dir}", "the folder {dir} has mode {mode} and must be 0700; fix it with: chmod 700 {dir}", "dir", "mode"), "prefs.outputs.permisos"),
		"prefs.outputs.ancestro_inseguro":     e("{dir} cuelga de {anc}, que otros usuarios pueden escribir (modo {mode}, dueño uid {uid}): otro usuario podría reemplazar la ruta; elige una carpeta bajo tu carpeta personal", "{dir} hangs from {anc}, which other users can write to (mode {mode}, owner uid {uid}): another user could replace the path; choose a folder under your home folder", "dir", "anc", "mode", "uid"),
		"prefs.outputs.permisos_win":          withReason(e("la carpeta {dir} da acceso a {sid}; solo pueden tenerlo tu usuario, SYSTEM y Administradores", "the folder {dir} gives access to {sid}; only your user, SYSTEM and Administrators may have it", "dir", "sid"), "prefs.outputs.permisos"),
		"prefs.outputs.permisos_orden_win":    withReason(e("la carpeta {dir} da acceso a {sid}; solo pueden tenerlo tu usuario, SYSTEM y Administradores; corrígelo en cmd con: icacls \"{dir}\" /inheritance:r {remove} /grant:r \"*{user}:(OI)(CI)F\" \"*S-1-5-18:(OI)(CI)F\" \"*S-1-5-32-544:(OI)(CI)F\"", "the folder {dir} gives access to {sid}; only your user, SYSTEM and Administrators may have it; fix it in cmd with: icacls \"{dir}\" /inheritance:r {remove} /grant:r \"*{user}:(OI)(CI)F\" \"*S-1-5-18:(OI)(CI)F\" \"*S-1-5-32-544:(OI)(CI)F\"", "dir", "sid", "remove", "user"), "prefs.outputs.permisos"),
		"prefs.outputs.ancestro_inseguro_win": withReason(e("{dir} cuelga de {anc}, donde {sid} puede escribir: otro usuario podría reemplazar la ruta; elige una carpeta bajo tu perfil de usuario", "{dir} hangs from {anc}, where {sid} can write: another user could replace the path; choose a folder under your user profile", "dir", "anc", "sid"), "prefs.outputs.ancestro_inseguro"),
		"prefs.outputs.no_escribible":         e("no se puede escribir en {dir}: {err}", "cannot write to {dir}: {err}", "dir", "err"),
		"prefs.outputs.issue":                 e("la carpeta de salidas guardada ({dir}) ya no es válida y se usa la de fábrica: {reason}", "the saved outputs folder ({dir}) is no longer valid and the factory one is used: {reason}", "dir", "reason"),
		"prefs.outputs.note":                  e("El cambio aplica a lo que empiece después: los trabajos y escuchas en curso conservan la carpeta con que arrancaron. Los datos de la carpeta anterior no se mueven.", "The change applies to what starts afterwards: jobs and listeners already running keep the folder they started with. Data in the previous folder is not moved."),
	})
	// Contrato para front: metadata.code es el motivo (lo que sigue a prefs.outputs.) y metadata.path la ruta.
	for k, e := range catalog {
		if _, ok := strings.CutPrefix(k, "prefs.outputs."); ok && slices.Contains(e.Args, "dir") {
			e.Meta, e.Extra = map[string]string{"code": strings.TrimPrefix(Reason(k), "prefs.outputs.")}, append(e.Extra, "path")
			catalog[k] = e
		}
	}
}

func withReason(e entry, reason string) entry { e.Reason = reason; return e }
