package i18n

// Instrucciones del servidor de archivos (internal/diag/fileserve: ServerHint, Hint, RedirectHint, SetcapHint).
// Los comandos de IOS y de nftables, las IP, los nombres de archivo y las contraseñas son datos y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"fileserve.hint.this_host":              e("IP-DE-ESTA-MÁQUINA", "IP-OF-THIS-MACHINE"),
		"fileserve.hint.server_path":            e("RUTA-DEL-SERVIDOR", "SERVER-PATH"),
		"fileserve.hint.warn_noperms_recv":      e("AVISO: la carpeta de recepción ({dir}) está en un volumen sin permisos por usuario: cualquier usuario del equipo puede leer o cambiar lo recibido", "WARNING: the receive folder ({dir}) is on a volume without per-user permissions: any user on this computer can read or change what you receive", "dir"),
		"fileserve.hint.warn_noperms_from":      e("AVISO: la carpeta que publicas ({dir}) está en un volumen sin permisos por usuario: cualquier usuario del equipo puede leer o cambiar lo que sirves", "WARNING: the folder you publish ({dir}) is on a volume without per-user permissions: any user on this computer can read or change what you serve", "dir"),
		"fileserve.hint.warn_unverified":        e("AVISO: no se pudieron revisar los permisos de {dir} ({err}): otro usuario podría cambiar lo que sirves", "WARNING: could not check the permissions of {dir} ({err}): another user could change what you serve", "dir", "err"),
		"fileserve.hint.warn_from_writable":     e("AVISO: la carpeta que publicas ({dir}) la pueden escribir otros ({who}): otro usuario puede reemplazar los archivos que sirves (por ejemplo, una imagen de firmware)", "WARNING: the folder you publish ({dir}) can be written by others ({who}): another user can replace the files you serve (for example, a firmware image)", "dir", "who"),
		"fileserve.hint.warn_from_writable_cmd": e("AVISO: la carpeta que publicas ({dir}) la pueden escribir otros ({who}): otro usuario puede reemplazar los archivos que sirves (por ejemplo, una imagen de firmware); quítales la escritura con: {cmd}", "WARNING: the folder you publish ({dir}) can be written by others ({who}): another user can replace the files you serve (for example, a firmware image); remove their write access with: {cmd}", "dir", "who", "cmd"),
		"fileserve.hint.head":                   e("En el equipo:", "On the device:"),
		"fileserve.hint.warn_udp":               e("AVISO: en UDP la lista de IP no autentica: la IP de origen se puede falsificar; úsala como filtro, no como seguridad, y solo en una red de confianza", "WARNING: over UDP the IP list does not authenticate: the source IP can be spoofed; use it as a filter, not as security, and only on a trusted network"),
		"fileserve.hint.warn_ftp":               e("AVISO: FTP manda el usuario y la contraseña en claro por la red; úsalo solo en un enlace directo o una red de confianza (SCP o SFTP no lo hacen)", "WARNING: FTP sends the user and password in clear text over the network; use it only on a direct link or a trusted network (SCP and SFTP do not)"),
		"fileserve.hint.ftp_passive":            e("(IOS usa FTP activo salvo que le pongas ip ftp passive: este servidor solo habla pasivo)", "(IOS uses active FTP unless you set ip ftp passive: this server only speaks passive)"),
		"fileserve.hint.ftp_cleanup":            e("al terminar, borra la credencial del equipo: conf t / no ip ftp password / end", "when done, remove the credential from the device: conf t / no ip ftp password / end"),
		"fileserve.hint.password":               e("(contraseña: {pass})", "(password: {pass})", "pass"),
		"fileserve.hint.fingerprint":            e("huella {n} de la llave de host: {fp} ({kind})", "host key fingerprint {n}: {fp} ({kind})", "n", "fp", "kind"),
		"fileserve.hint.name_spaces":            e("el nombre «{name}» tiene espacios: IOS no puede pedirlo por {proto}; renómbralo", "the name «{name}» has spaces: IOS cannot request it over {proto}; rename it", "name", "proto"),
		"fileserve.err.port_busy":               e("el puerto {port} ya está en uso, probablemente por otro servicio (en Windows, el servidor OpenSSH usa el 22); páralo o elige un puerto alto, por ejemplo 2222", "port {port} is already in use, probably by another service (on Windows, the OpenSSH server uses 22); stop it or pick a high port, for example 2222", "port"),
		"fileserve.hint.sftp_note":              e("(IOS 15.2 puede no traer cliente SFTP; si copy sftp: no existe, usa scp)", "(IOS 15.2 may not have an SFTP client; if copy sftp: does not exist, use scp)"),
		"fileserve.hint.std_port":               e("IOS usa el puerto {std} de {proto} y no deja elegir otro; escucho en el {port}. Redirige el {std} a este servidor (la regla la corres tú):", "IOS uses port {std} for {proto} and does not let you choose another; I listen on {port}. Redirect {std} to this server (you run the rule):", "std", "proto", "port"),
		"fileserve.hint.std_port_ok":            e("IOS usa el puerto {std} de {proto} y aquí se escucha directamente en ese puerto.", "IOS uses port {std} for {proto} and this server listens directly on that port.", "std", "proto"),
		"fileserve.hint.redirect":               e("redirección (recomendada): {cmd}", "redirect (recommended): {cmd}", "cmd"),
		"fileserve.hint.nft_remove":             e("(quitar al terminar: {cmd})", "(remove when done: {cmd})", "cmd"),
		"fileserve.hint.tftp_redir":             e("IOS siempre usa el puerto 69; redirígelo a este servidor (la regla la corres tú):", "IOS always uses port 69; redirect it to this server (you run the rule):"),
	})
}
