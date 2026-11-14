package i18n

// Descripción de los campos de los archivos de import de scripts y colecciones (scripts/formato.go). Los nombres de
// campo, los valores fijos («usuario», «biblioteca», «favoritos») y las listas cerradas no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	const name = "De 1 a {max} caracteres, sin espacios en los extremos ni caracteres de control. Único sin importar mayúsculas"
	const nameEn = "1 to {max} characters, no leading or trailing spaces and no control characters. Unique regardless of case"
	add(map[string]entry{
		"scriptsfmt.type.date":      e("fecha RFC 3339", "RFC 3339 date"),
		"scriptsfmt.type.array":     e("arreglo", "array"),
		"scriptsfmt.type.text":      e("texto", "text"),
		"scriptsfmt.type.int":       e("entero", "integer"),
		"scriptsfmt.type.text_list": e("lista de texto", "list of text"),

		"scriptsfmt.desc.formato":        e("Tipo de archivo; debe ser exactamente el de la plantilla", "File type; it must be exactly the one in the template"),
		"scriptsfmt.desc.version":        e("Versión del formato; solo se acepta la {v}", "Format version; only {v} is accepted", "v"),
		"scriptsfmt.desc.exportado":      e("Fecha del export (RFC 3339); informativa", "Export date (RFC 3339); informational"),
		"scriptsfmt.desc.sha256":         e("Suma SHA-256 (hex) del JSON canónico de los datos; protege contra un archivo dañado, no prueba quién lo hizo. Opcional: sin ella se valida campo por campo y la vista previa avisa", "SHA-256 sum (hex) of the canonical JSON of the data; it protects against a damaged file and does not prove who made it. Optional: without it each field is validated and the preview warns"),
		"scriptsfmt.desc.scripts":        e("Arreglo de scripts, hasta {max}", "Array of scripts, up to {max}", "max"),
		"scriptsfmt.desc.colecciones":    e("Arreglo de colecciones, hasta {max}", "Array of collections, up to {max}", "max"),
		"scriptsfmt.desc.col_scripts":    e("Arreglo con los scripts de usuario que las colecciones referencian (los de la biblioteca viajan solo por ID)", "Array with the user scripts the collections reference (library ones travel by ID only)"),
		"scriptsfmt.desc.script_id":      e("32 caracteres hexadecimales (usuario) o «lib-<nombre>» (biblioteca). Sin repetir en el archivo", "32 hexadecimal characters (user) or \"lib-<name>\" (library). Not repeated in the file"),
		"scriptsfmt.desc.col_script_id":  e("32 caracteres hexadecimales; sin repetir en el archivo", "32 hexadecimal characters; not repeated in the file"),
		"scriptsfmt.desc.name":           e(name, nameEn, "max"),
		"scriptsfmt.desc.one_of":         e("Una de: {list}", "One of: {list}", "list"),
		"scriptsfmt.desc.description":    e("Hasta {max} caracteres", "Up to {max} characters", "max"),
		"scriptsfmt.desc.commands":       e("De 1 a {max} comandos de hasta {len} caracteres, ASCII imprimible (sin tabuladores ni acentos). Una línea que empieza con «!» en la columna 0 es comentario", "1 to {max} commands of up to {len} characters, printable ASCII (no tabs or accents). A line starting with \"!\" in column 0 is a comment", "max", "len"),
		"scriptsfmt.desc.tags":           e("Hasta {max} etiquetas, cada una de 1 a 24 caracteres entre minúsculas, dígitos y guion, sin repetir", "Up to {max} tags, each 1 to 24 characters of lowercase letters, digits and hyphen, not repeated", "max"),
		"scriptsfmt.desc.origin":         e("«usuario» o «biblioteca»; lo de biblioteca que no coincide con la local se importa como script del usuario", "\"usuario\" or \"biblioteca\"; library content that does not match the local one is imported as a user script"),
		"scriptsfmt.desc.col_origin":     e("Siempre «usuario»", "Always \"usuario\""),
		"scriptsfmt.desc.script_created": e("Fecha de creación (RFC 3339); al importar se usa la del momento", "Creation date (RFC 3339); on import the current time is used"),
		"scriptsfmt.desc.script_updated": e("Fecha de edición (RFC 3339); al importar se usa la del momento", "Edit date (RFC 3339); on import the current time is used"),
		"scriptsfmt.desc.col_id":         e("32 caracteres hexadecimales, o «favoritos» (la colección por defecto, que se fusiona y nunca se reemplaza). Sin repetir en el archivo", "32 hexadecimal characters, or \"favoritos\" (the default collection, which is merged and never replaced). Not repeated in the file"),
		"scriptsfmt.desc.col_name":       e(name+"; «favoritos» se llama «{fav}»", nameEn+"; \"favoritos\" is named \"{fav}\"", "max", "fav"),
		"scriptsfmt.desc.order":          e("Posición al exportar; al importar las nuevas quedan al final", "Position on export; on import the new ones go last"),
		"scriptsfmt.desc.script_ids":     e("IDs de script en orden, sin repetir, hasta {max}. Los de usuario deben viajar en «scripts»; un «lib-*» que la biblioteca local no trae se avisa y se omite", "Script IDs in order, not repeated, up to {max}. User ones must travel in \"scripts\"; a \"lib-*\" the local library does not have is reported and skipped", "max"),
		"scriptsfmt.desc.col_created":    e("Fecha de creación (RFC 3339)", "Creation date (RFC 3339)"),
		"scriptsfmt.desc.col_updated":    e("Fecha de edición (RFC 3339)", "Edit date (RFC 3339)"),
	})
}
