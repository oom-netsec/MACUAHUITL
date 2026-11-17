package i18n

// Fase 44d: carpetas de hosts.
func init() {
	e := func(es, en string) entry { return entry{Es: es, En: en, Args: tplArgs(es, en)} }
	add(map[string]entry{
		"hosts.err.folder_exists":    e("ya hay una carpeta llamada {name:q}", "there is already a folder named {name:q}"),
		"hosts.err.folder_no":        e("no hay una carpeta llamada {name:q}", "there is no folder named {name:q}"),
		"hosts.err.folders_full":     e("la libreta llegó a {max} carpetas", "the address book has reached {max} folders"),
		"hosts.err.folder_not_empty": e("la carpeta {name:q} tiene {host_count} host(s): confirma para dejarlos sin carpeta (no se borra ninguno)", "the folder {name:q} has {host_count} host(s): confirm to leave them without a folder (none is deleted)"),
		"hosts.err.move_ids":         e("mover hosts pide de 1 a {max} ids", "moving hosts takes 1 to {max} ids"),
	})
}
