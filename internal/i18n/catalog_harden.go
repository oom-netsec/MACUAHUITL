package i18n

// Avisos del endurecimiento del núcleo (internal/sys): la auditoría los guarda en inglés; la consola de macuahuitld los
// imprime en el idioma del proceso.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"harden.memlock_read":  e("no se pudo leer RLIMIT_MEMLOCK: {cause}", "could not read RLIMIT_MEMLOCK: {cause}", "cause"),
		"harden.memlock_limit": e("RLIMIT_MEMLOCK es de {bytes} bytes; no toda la memoria queda bloqueada. Pon LimitMEMLOCK=infinity en la unidad de systemd", "RLIMIT_MEMLOCK is {bytes} bytes; not all memory is locked. Set LimitMEMLOCK=infinity in the systemd unit", "bytes"),
		"harden.mlockall":      e("mlockall falló; la memoria del núcleo podría ir a swap: {cause}", "mlockall failed; core memory could be swapped out: {cause}", "cause"),
		"harden.nodump":        e("no se pudo marcar el proceso como no volcable: {cause}", "could not mark the process as non-dumpable: {cause}", "cause"),
		"harden.nocore":        e("no se pudieron desactivar los volcados de memoria (core dumps): {cause}", "could not disable core dumps: {cause}", "cause"),
		"harden.swap":          e("swap posiblemente sin cifrar: {dev}", "swap possibly unencrypted: {dev}", "dev"),
		"harden.hibernation":   e("hibernación configurada (resume={resume}): la memoria podría escribirse en disco", "hibernation configured (resume={resume}): memory could be written to disk", "resume"),
		"harden.prefix":        e("aviso:", "warning:"),
	})
}
