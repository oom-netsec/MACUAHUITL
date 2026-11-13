package i18n

// Importación de scripts y colecciones (internal/scripts: importar.go, coleccion.go, exchange.go): errores del archivo
// y de las decisiones. Los nombres e ID del archivo son datos.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"scripts.imp.dec_ids":                e("decisión para IDs que no están en el archivo: {ids}", "decision for IDs that are not in the file: {ids}", "ids"),
		"scripts.imp.dec_cols":               e("decisión para colecciones que no están en el archivo: {ids}", "decision for collections that are not in the file: {ids}", "ids"),
		"scripts.imp.dec_unknown":            e("decisión {dec:q} desconocida para {id}", "unknown decision {dec:q} for {id}", "dec", "id"),
		"scripts.imp.only_skip":              e("{id} es {state:q}: solo se puede omitir", "{id} is {state:q}: it can only be skipped", "id", "state"),
		"scripts.imp.missing":                e("falta la decisión de {n} conflicto(s): {ids}", "the decision for {n} conflict(s) is missing: {ids}", "n", "ids"),
		"scripts.imp.missing_cols":           e("falta la decisión de {n} conflicto(s) de colecciones: {ids}", "the decision for {n} collection conflict(s) is missing: {ids}", "n", "ids"),
		"scripts.imp.lib_clash":              e("{name} choca con un script de la biblioteca, que no se reemplaza: renómbralo u omítelo", "{name} clashes with a library script, which is not replaced: rename it or skip it", "name"),
		"scripts.imp.fav_clash":              e("{name} choca con {id}, que no se reemplaza: renómbrala u omítela", "{name} clashes with {id}, which is not replaced: rename it or skip it", "name", "id"),
		"scripts.imp.dup_replace":            e("dos decisiones reemplazan el mismo script guardado ({id})", "two decisions replace the same stored script ({id})", "id"),
		"scripts.imp.dup_replace_col":        e("dos decisiones reemplazan la misma colección guardada ({id})", "two decisions replace the same stored collection ({id})", "id"),
		"scripts.imp.replace_dup_name":       e("reemplazar {id} dejaría dos scripts con el nombre {name:q}", "replacing {id} would leave two scripts named {name:q}", "id", "name"),
		"scripts.imp.replace_dup_col":        e("reemplazar {id} dejaría dos colecciones con el nombre {name:q}", "replacing {id} would leave two collections named {name:q}", "id", "name"),
		"scripts.imp.name_exists":            e("el nombre {name:q} ya existe", "the name {name:q} already exists", "name"),
		"scripts.imp.item":                   e("{name}: {cause}", "{name}: {cause}", "name", "cause"),
		"scripts.imp.max_cols":               e("el archivo trae {n} colecciones; el tope es {max}", "the file has {n} collections; the limit is {max}", "n", "max"),
		"scripts.imp.max_scripts":            e("el archivo trae {n} scripts; el tope es {max}", "the file has {n} scripts; the limit is {max}", "n", "max"),
		"scripts.imp.lib_by_id":              e("script {name:q}: los de la biblioteca viajan solo por ID", "script {name:q}: library scripts travel only by ID", "name"),
		"scripts.imp.ref_missing":            e("la colección {name} referencia al script {id}, que no viaja en el archivo", "the collection {name} references the script {id}, which is not in the file", "name", "id"),
		"scripts.imp.too_big":                e("el archivo pasa de 5 MB", "the file is larger than 5 MB"),
		"scripts.imp.not_file.scripts":       e("no es un archivo de scripts: {cause}", "not a scripts file: {cause}", "cause"),
		"scripts.imp.not_file.colecciones":   e("no es un archivo de colecciones: {cause}", "not a collections file: {cause}", "cause"),
		"scripts.imp.format":                 e("formato {got:q}: se esperaba {want:q}", "format {got:q}: expected {want:q}", "got", "want"),
		"scripts.imp.version":                e("versión {got} no soportada (solo la {want})", "version {got} not supported (only {want})", "got", "want"),
		"scripts.imp.trailing":               e("hay datos después del JSON del archivo", "there is data after the JSON of the file"),
		"scripts.imp.unreadable.scripts":     e("scripts ilegibles: {cause}", "unreadable scripts: {cause}", "cause"),
		"scripts.imp.unreadable.colecciones": e("colecciones ilegibles: {cause}", "unreadable collections: {cause}", "cause"),
		"scripts.imp.checksum":               e("la suma de verificación no coincide: el archivo está dañado o fue modificado", "the checksum does not match: the file is damaged or was modified"),
		"scripts.imp.warn_lib_skip":          e("colección {name:q}: el script {id} no está en la biblioteca local; se omitirá", "collection {name:q}: the script {id} is not in the local library; it will be skipped", "name", "id"),
		"scripts.imp.warn_lib_skipped":       e("colección {name:q}: el script {id} no está en la biblioteca local; se omitió", "collection {name:q}: the script {id} is not in the local library; it was skipped", "name", "id"),
		"scripts.imp.warn_not_imported":      e("colección {name:q}: el script {id} no se importó; se quitó de la colección", "collection {name:q}: the script {id} was not imported; it was removed from the collection", "name", "id"),
		"scripts.imp.no_sum":                 e("archivo sin suma de verificación", "file without a checksum"),
	})
}
