package i18n

// Errores de la bóveda (internal/vault): son los centinelas que el servicio traduce a gRPC con VaultErr.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"vault.err.not_backup":      e("vault: no es un respaldo de bóveda de MACUAHUITL", "vault: not a MACUAHUITL vault backup"),
		"vault.err.short_phrase":    e("vault: la frase del respaldo debe tener al menos 12 caracteres", "vault: the backup passphrase must be at least 12 characters long"),
		"vault.err.same_phrase":     e("vault: la frase del respaldo debe ser distinta de la contraseña maestra", "vault: the backup passphrase must differ from the master password"),
		"vault.err.backup_exists":   e("vault: el archivo de respaldo ya existe", "vault: the backup file already exists"),
		"vault.err.not_regular":     e("vault: la ruta existe y no es un archivo regular", "vault: the path exists and is not a regular file"),
		"vault.err.backup_params":   e("vault: los parámetros de Argon2id de la bóveda pasan de lo que admite un respaldo", "vault: the vault Argon2id parameters exceed what a backup supports"),
		"vault.err.too_many":        e("vault: el respaldo trae demasiadas credenciales", "vault: the backup has too many credentials"),
		"vault.err.empty_password":  e("vault: contraseña maestra vacía", "vault: empty master password"),
		"vault.err.wrong_password":  e("vault: contraseña maestra incorrecta", "vault: wrong master password"),
		"vault.err.locked":          e("vault: bóveda cerrada", "vault: vault is locked"),
		"vault.err.not_found":       e("vault: credencial no encontrada", "vault: credential not found"),
		"vault.err.corrupt":         e("vault: archivo dañado o alterado", "vault: file damaged or tampered with"),
		"vault.err.exists":          e("vault: la bóveda ya existe", "vault: the vault already exists"),
		"vault.err.weak_params":     e("vault: parámetros de Argon2id por debajo del mínimo", "vault: Argon2id parameters below the minimum"),
		"vault.err.reserved":        e("vault: entrada reservada del sistema, no es una credencial de conexión", "vault: reserved system entry, not a connection credential"),
		"vault.err.window_too_long": e("vault: la ventana debe terminar en el futuro y durar como máximo 96 h", "vault: the window must end in the future and last at most 96 h"),
	})
}
