package i18n

// Etiquetas de las acciones de auditoría. La clave de la acción (hosts.crear…) queda guardada tal cual en la cadena de
// hashes y no se reescribe: aquí solo está lo que se muestra (audit.ActionLabel).
func init() {
	e := func(es, en string) entry { return entry{Es: es, En: en} }
	add(map[string]entry{
		"audit.action.hosts.crear":    e("host creado", "host created"),
		"audit.action.hosts.editar":   e("host editado", "host edited"),
		"audit.action.hosts.borrar":   e("host borrado", "host deleted"),
		"audit.action.hosts.importar": e("hosts importados", "hosts imported"),
		"audit.action.hosts.exportar": e("hosts exportados", "hosts exported"),
	})
}
