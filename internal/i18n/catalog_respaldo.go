package i18n

// Respaldo cifrado de la bóveda (internal/core/respaldo.go): exportar e importar con vista previa y decisiones.
// Las etiquetas de credencial viajan como argumentos; nunca se citan secretos ni frases.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"respaldo.err.token":            e("token de importación desconocido; abre el respaldo de nuevo", "unknown import token; open the backup again"),
		"respaldo.err.expired":          e("la vista previa venció; vuelve a abrir el respaldo", "the preview expired; open the backup again"),
		"respaldo.err.path_abs":         e("la ruta debe ser absoluta", "the path must be absolute"),
		"respaldo.err.wrong_phrase":     e("la frase del respaldo es incorrecta (o el archivo está alterado)", "the backup passphrase is wrong (or the file has been tampered with)"),
		"respaldo.err.corrupt":          e("el respaldo está dañado o alterado", "the backup is damaged or has been tampered with"),
		"respaldo.err.confirm":          e("el respaldo contiene todas tus credenciales en un solo archivo: quien tenga el archivo y la frase las tiene todas; confirma para continuar", "the backup contains all your credentials in a single file: whoever has the file and the passphrase has them all; confirm to continue"),
		"respaldo.err.in_data_dir":      e("el respaldo no puede guardarse dentro de la carpeta de datos del núcleo (ahí viven la bóveda y su copia): elige otra carpeta", "the backup cannot be saved inside the core data folder (the vault and its copy live there): choose another folder"),
		"respaldo.err.locked":           e("la bóveda está cerrada: desbloquéala y abre el respaldo de nuevo", "the vault is locked: unlock it and open the backup again"),
		"respaldo.err.decision_unknown": e("decisión para una credencial que no está en el respaldo", "decision for a credential that is not in the backup"),
		"respaldo.err.decision_dup":     e("decisión repetida para {label:q}", "repeated decision for {label:q}", "label"),
		"respaldo.err.action":           e("acción {action:q} desconocida; usa renombrar, reemplazar u omitir", "unknown action {action:q}; use \"renombrar\", \"reemplazar\" or \"omitir\"", "action"),
		"respaldo.err.undecided":        e("falta decidir qué hacer con {label:q}: renombrar, reemplazar u omitir", "you still need to decide what to do with {label:q}: \"renombrar\", \"reemplazar\" or \"omitir\"", "label"),
		"respaldo.err.double_replace":   e("dos credenciales del respaldo reemplazarían la misma credencial de la bóveda ({label:q}): elige otra decisión para una de ellas", "two credentials of the backup would replace the same credential of the vault ({label:q}): choose another decision for one of them", "label"),
	})
}
