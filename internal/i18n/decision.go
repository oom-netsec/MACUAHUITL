package i18n

// Decision lleva el verbo de una decisión de importación a su valor canónico en inglés (rename, replace, skip).
// Los verbos en español (renombrar, reemplazar, omitir) siguen valiendo como alias para no romper scripts; lo
// desconocido pasa tal cual para que quien valida lo rechace.
func Decision(a string) string {
	switch a {
	case "renombrar":
		return "rename"
	case "reemplazar":
		return "replace"
	case "omitir":
		return "skip"
	}
	return a
}
