package i18n

// Cierre del idioma del asistente (fase 30e): el rechazo del plan, los errores del ejecutor y de la rotación, y los textos de la rotación
// que van como salida de la ejecución. En es, el texto de siempre, byte por byte; ningún argumento lleva secretos.
func init() {
	add(map[string]entry{
		"assist.no_difference":              {Es: "assist: el equipo ya coincide con el respaldo", En: "assist: the device already matches the backup"},
		"assist.invalid_plan":               {Es: "assist: plan inválido: {detail}", En: "assist: invalid plan: {detail}", Args: []string{"detail"}},
		"assist.svc.unknown_device":         {Es: "equipo {device:q} desconocido", En: "unknown device {device:q}", Args: []string{"device"}},
		"assist.svc.no_vault":               {Es: "la bóveda no existe", En: "the vault does not exist"},
		"assist.svc.vault_read_failed":      {Es: "no se pudo leer la credencial de la bóveda: {cause}", En: "could not read the credential from the vault: {cause}", Args: []string{"cause"}},
		"assist.svc.vault_save_prev_failed": {Es: "la bóveda no pudo guardar la credencial anterior: {cause}", En: "the vault could not save the previous credential: {cause}", Args: []string{"cause"}},
		"assist.svc.vault_save_new_failed":  {Es: "la bóveda no pudo guardar la credencial nueva (la anterior quedó como {prev:q}): {cause}", En: "the vault could not save the new credential (the previous one was kept as {prev:q}): {cause}", Args: []string{"cause", "prev"}},
		"assist.run.new_session_ok":         {Es: "la sesión nueva con {user} entró", En: "the new session with {user} logged in", Args: []string{"user"}},
		"assist.run.saved_no_credential":    {Es: "write memory salió bien; no se indicó credencial de la bóveda que actualizar", En: "write memory succeeded; no vault credential to update was given"},
		"assist.run.saved_vault_updated":    {Es: "la bóveda quedó con la credencial nueva; la anterior se conserva como {prev:q} (bórrala a mano cuando ya no haga falta)", En: "the vault now holds the new credential; the previous one is kept as {prev:q} (delete it by hand when no longer needed)", Args: []string{"prev"}},
		"assist.run.missing_runner_parts":   {Es: "assist: faltan el ejecutor, la auditoría o el identificador", En: "assist: the executor, the audit or the identifier is missing"},
	})
}
