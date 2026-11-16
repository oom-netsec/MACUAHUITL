package i18n

// Avisos del endurecimiento del núcleo (internal/sys): la auditoría los guarda en inglés; la consola de macuahuitld los
// imprime en el idioma del proceso.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"harden.memlock_read":        e("no se pudo leer RLIMIT_MEMLOCK: {cause}", "could not read RLIMIT_MEMLOCK: {cause}", "cause"),
		"harden.memlock_limit":       e("RLIMIT_MEMLOCK es de {bytes} bytes; no toda la memoria queda bloqueada. súbelo para el gestor de usuario con LimitMEMLOCK=infinity en /etc/systemd/system/user@.service.d/ (README, Install)", "RLIMIT_MEMLOCK is {bytes} bytes; not all memory is locked. raise it for the user manager with LimitMEMLOCK=infinity in /etc/systemd/system/user@.service.d/ (README, Install)", "bytes"),
		"harden.mlockall":            e("mlockall falló; la memoria del núcleo podría ir a swap: {cause}", "mlockall failed; core memory could be swapped out: {cause}", "cause"),
		"harden.nodump":              e("no se pudo marcar el proceso como no volcable: {cause}", "could not mark the process as non-dumpable: {cause}", "cause"),
		"harden.nocore":              e("no se pudieron desactivar los volcados de memoria (core dumps): {cause}", "could not disable core dumps: {cause}", "cause"),
		"harden.swap":                e("swap posiblemente sin cifrar: {dev}", "swap possibly unencrypted: {dev}", "dev"),
		"harden.hibernation":         e("hibernación configurada (resume={resume}): la memoria podría escribirse en disco", "hibernation configured (resume={resume}): memory could be written to disk", "resume"),
		"harden.err.root":            e("no corre como root (spec §2); usa systemctl --user", "does not run as root (spec §2); use systemctl --user"),
		"harden.err.runtime_dir":     e("XDG_RUNTIME_DIR no está definido", "XDG_RUNTIME_DIR is not set"),
		"harden.err.elevated":        e("no corre elevado (ADR 0012): una cuenta con UAC desactivado o el Administrador integrado siempre corre elevada; usa una cuenta estándar o una de administrador con UAC activo", "does not run elevated (ADR 0012): an account with UAC turned off, or the built-in Administrator, always runs elevated; use a standard account or an administrator account with UAC on"),
		"harden.err.localappdata":    e("LOCALAPPDATA no está definido o no es una ruta absoluta", "LOCALAPPDATA is not set or is not an absolute path"),
		"harden.wer":                 e("no se pudo excluir al núcleo de los reportes de error de Windows (WER): {cause}", "could not exclude the core from Windows Error Reporting (WER): {cause}", "cause"),
		"harden.err.lockquota":       e("el núcleo no arranca: no se pudo subir el mínimo del working set y memguard no podría bloquear las llaves en memoria ({cause})", "the core does not start: could not raise the minimum working set, so memguard could not lock keys in memory ({cause})", "cause"),
		"harden.hibernation_win":     e("hibernación activada (HibernateEnabled=1): hiberfil.sys guarda la memoria en disco; activa BitLocker", "hibernation is on (HibernateEnabled=1): hiberfil.sys writes memory to disk; turn on BitLocker"),
		"harden.hibernation_unknown": e("no se pudo comprobar si la hibernación está activada (usa BitLocker de todos modos): {cause}", "could not check whether hibernation is on (use BitLocker anyway): {cause}", "cause"),
		"harden.pagefile":            e("archivo de paginación activo ({files}): la memoria podría escribirse en disco sin cifrar; activa BitLocker", "paging file is on ({files}): memory could be written to disk unencrypted; turn on BitLocker", "files"),
		"harden.pagefile_unknown":    e("no se pudo comprobar el archivo de paginación (usa BitLocker de todos modos): {cause}", "could not check the paging file (use BitLocker anyway): {cause}", "cause"),
		"ipc.err.pipe_other_user":    e("el canal del núcleo lo tiene otro usuario (el pipe ya existe y no se puede abrir)", "the core channel is held by another user (the pipe already exists and cannot be opened)"),
		"harden.prefix":              e("aviso:", "warning:"),
	})
}
