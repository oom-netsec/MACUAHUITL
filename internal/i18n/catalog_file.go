package i18n

// Archivos: guardar sin sobrescribir. El motivo es file.exists y la metadata lleva la ruta.
func init() {
	add(map[string]entry{
		"file.err.path_abs": {Es: "la ruta debe ser absoluta", En: "the path must be absolute"},
		"file.err.no_drive": {Es: "la ruta {path:q} debe empezar con una letra de unidad (como C:\\carpeta): no se aceptan rutas de red (\\\\servidor\\recurso), \\\\?\\ ni \\\\.\\", En: "the path {path:q} must start with a drive letter (like C:\\folder): network paths (\\\\server\\share), \\\\?\\ and \\\\.\\ are not accepted", Args: []string{"path"}},
		"file.exists":       {Es: "el archivo ya existe", En: "the file already exists", Extra: []string{"path"}},
		"file.exists.vault": {Reason: "file.exists", Es: "vault: el archivo de respaldo ya existe", En: "vault: the backup file already exists", Extra: []string{"path"}},
		"file.exists.save":  {Reason: "file.exists", Es: "guardar: el archivo ya existe", En: "save: the file already exists", Extra: []string{"path"}},
	})
}
