package i18n

// Archivos: guardar sin sobrescribir. El motivo es file.exists y la metadata lleva la ruta.
func init() {
	add(map[string]entry{
		"file.err.path_abs": {Es: "la ruta debe ser absoluta", En: "the path must be absolute"},
		"file.exists":       {Es: "el archivo ya existe", En: "the file already exists", Extra: []string{"path"}},
		"file.exists.vault": {Reason: "file.exists", Es: "vault: el archivo de respaldo ya existe", En: "vault: the backup file already exists", Extra: []string{"path"}},
		"file.exists.save":  {Reason: "file.exists", Es: "guardar: el archivo ya existe", En: "save: the file already exists", Extra: []string{"path"}},
	})
}
