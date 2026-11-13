package i18n

// Fase 30d: validaciones sueltas de servicios que seguían con texto fijo en español (archivos de export/import,
// seguridad, preferencias, host y herramientas de diagnóstico).
func init() {
	e := func(es, en string) entry { return entry{Es: es, En: en} }
	add(map[string]entry{
		"file.err.export_not_regular": e("la ruta existe y no es un archivo regular", "the path exists and is not a regular file"),
		"diag.err.no_tool":            e("herramienta no indicada", "no tool given"),
		"security.err.no_vault":       e("no hay bóveda", "there is no vault"),
		"security.err.bad_server":     e("servidor inválido", "invalid server"),
		"security.err.bad_port":       e("puerto inválido", "invalid port"),
		"security.err.key_password":   e("contraseña de la llave incorrecta", "wrong key password"),
		"security.err.plain_key":      e("exportar la llave en claro requiere marcar include_plain_key", "exporting the key in the clear requires include_plain_key"),
		"security.err.too_big":        e("entrada demasiado grande", "input too large"),
		"security.err.debug_too_big":  e("entrada demasiado grande: el máximo es 1 MiB de texto de debug", "input too large: the maximum is 1 MiB of debug text"),
		"field.err.first_open":        e("el primer mensaje debe abrir el puerto", "the first message must open the port"),
		"prefs.err.bad_key":           e("clave de preferencia inválida", "invalid preference key"),
		"prefs.err.bad_language":      e("ui.language debe ser es o en", "ui.language must be es or en"),
		"prefs.err.too_big":           e("valor de preferencia mayor de 4 KiB", "preference value larger than 4 KiB"),
		"hosts.err.missing":           e("falta el host", "the host is missing"),
		"hosts.err.no_credential":     e("la credencial no existe en la bóveda (o es una entrada del sistema)", "the credential does not exist in the vault (or it is a system entry)"),
		"hosts.err.nothing_to_export": e("no hay hosts que exportar", "there are no hosts to export"),
		"hosts.err.export_too_big":    e("el archivo pasaría de 5 MB y el import lo rechazaría; exporta menos hosts", "the file would exceed 5 MB and the import would reject it; export fewer hosts"),
		"hosts.err.token":             e("token de importación desconocido; abre el archivo de nuevo", "unknown import token; open the file again"),
		"hosts.err.expired":           e("la vista previa venció; vuelve a abrir el archivo", "the preview expired; open the file again"),
		"hosts.err.format":            e("pida el formato csv o json", "ask for the csv or json format"),
	})
}
