package i18n

// Errores de la bóveda (internal/vault): son los centinelas que el servicio traduce a gRPC con VaultErr.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"vault.err.not_backup":         e("vault: no es un respaldo de bóveda de MACUAHUITL", "vault: not a MACUAHUITL vault backup"),
		"vault.err.short_phrase":       e("vault: la frase del respaldo debe tener al menos 12 caracteres", "vault: the backup passphrase must be at least 12 characters long"),
		"vault.err.same_phrase":        e("vault: la frase del respaldo debe ser distinta de la contraseña maestra", "vault: the backup passphrase must differ from the master password"),
		"vault.err.backup_exists":      e("vault: el archivo de respaldo ya existe", "vault: the backup file already exists"),
		"vault.err.not_regular":        e("vault: la ruta existe y no es un archivo regular", "vault: the path exists and is not a regular file"),
		"vault.err.backup_params":      e("vault: los parámetros de Argon2id de la bóveda pasan de lo que admite un respaldo", "vault: the vault Argon2id parameters exceed what a backup supports"),
		"vault.err.too_many":           e("vault: el respaldo trae demasiadas credenciales", "vault: the backup has too many credentials"),
		"vault.err.empty_password":     e("vault: contraseña maestra vacía", "vault: empty master password"),
		"vault.err.wrong_password":     e("vault: contraseña maestra incorrecta", "vault: wrong master password"),
		"vault.err.locked":             e("vault: bóveda cerrada", "vault: vault is locked"),
		"vault.err.not_found":          e("vault: credencial no encontrada", "vault: credential not found"),
		"vault.err.corrupt":            e("vault: archivo dañado o alterado", "vault: file damaged or tampered with"),
		"vault.err.field_too_long":     e("vault: un campo de la credencial pasa de {max}", "vault: a credential field is longer than {max}", "max"),
		"vault.err.key_invalid":        e("vault: la llave SSH privada de la credencial {label:q} no es válida (no se puede leer o lleva frase)", "vault: the private SSH key of credential {label:q} is not valid (it cannot be parsed or it is passphrase-protected)", "label"),
		"vault.err.exists":             e("vault: la bóveda ya existe", "vault: the vault already exists"),
		"vault.err.weak_params":        e("vault: parámetros de Argon2id por debajo del mínimo", "vault: Argon2id parameters below the minimum"),
		"vault.err.reserved":           e("vault: entrada reservada del sistema, no es una credencial de conexión", "vault: reserved system entry, not a connection credential"),
		"vault.err.no_key":             e("vault: la credencial no tiene llave SSH", "vault: the credential has no SSH key"),
		"vault.err.not_key_credential": e("vault: la credencial no es de tipo llave (solo una llave, sin contraseña ni enable)", "vault: the credential is not a key credential (key only, no password or enable secret)"),
		"vault.err.key_credential":     e("vault: una credencial de tipo llave no se reemplaza por aquí: use regenerar llave", "vault: a key credential cannot be replaced here: use regenerate key"),
		"vault.err.no_key_import":      e("vault: no se importan llaves privadas; genere una con generar llave", "vault: private keys are not imported; generate one with generate key"),
		"vault.err.key_unsupported":    e("vault: solo se deriva la pública de una llave ed25519 OpenSSH sin frase, como las que genera MACUAHUITL", "vault: the public key can only be derived from an unencrypted OpenSSH ed25519 key, like the ones MACUAHUITL generates"),
		"vault.err.rekey_confirm":      e("vault: regenerar la llave invalida la pública vieja en cada equipo donde esté; confirme", "vault: regenerating the key invalidates the old public key on every host that has it; confirm"),
		"vault.err.window_too_long":    e("vault: la ventana debe terminar en el futuro y durar como máximo 96 h", "vault: the window must end in the future and last at most 96 h"),
	})
}
