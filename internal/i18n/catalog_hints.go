package i18n

// Instrucciones del servidor de archivos (internal/diag/fileserve: ServerHint, Hint, RedirectHint, SetcapHint).
// Los comandos de IOS y de nftables, las IP, los nombres de archivo y las contraseñas son datos y no se traducen.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"fileserve.hint.this_host":   e("IP-DE-ESTA-MÁQUINA", "IP-OF-THIS-MACHINE"),
		"fileserve.hint.server_path": e("RUTA-DEL-SERVIDOR", "SERVER-PATH"),
		"fileserve.hint.head":        e("En el equipo:", "On the device:"),
		"fileserve.hint.warn_udp":    e("AVISO: en UDP la lista de IP no autentica: la IP de origen se puede falsificar; úsala como filtro, no como seguridad, y solo en una red de confianza", "WARNING: over UDP the IP list does not authenticate: the source IP can be spoofed; use it as a filter, not as security, and only on a trusted network"),
		"fileserve.hint.warn_ftp":    e("AVISO: FTP manda el usuario y la contraseña en claro por la red; úsalo solo en un enlace directo o una red de confianza (SCP o SFTP no lo hacen)", "WARNING: FTP sends the user and password in clear text over the network; use it only on a direct link or a trusted network (SCP and SFTP do not)"),
		"fileserve.hint.ftp_passive": e("(IOS usa FTP activo salvo que le pongas ip ftp passive: este servidor solo habla pasivo)", "(IOS uses active FTP unless you set ip ftp passive: this server only speaks passive)"),
		"fileserve.hint.ftp_cleanup": e("al terminar, borra la credencial del equipo: conf t / no ip ftp password / end", "when done, remove the credential from the device: conf t / no ip ftp password / end"),
		"fileserve.hint.password":    e("(contraseña: {pass})", "(password: {pass})", "pass"),
		"fileserve.hint.fingerprint": e("huella de la llave de host {n} (ed25519, RSA): {fp}", "host key fingerprint {n} (ed25519, RSA): {fp}", "n", "fp"),
		"fileserve.hint.sftp_note":   e("(IOS 15.2 puede no traer cliente SFTP; si copy sftp: no existe, usa scp)", "(IOS 15.2 may not have an SFTP client; if copy sftp: does not exist, use scp)"),
		"fileserve.hint.std_port":    e("IOS usa el puerto {std} de {proto} y no deja elegir otro; escucho en el {port}. Sin privilegios para la app:", "IOS uses port {std} for {proto} and does not let you choose another; I listen on {port}. Without giving the app privileges:", "std", "proto", "port"),
		"fileserve.hint.redirect":    e("redirección (recomendada): {cmd}", "redirect (recommended): {cmd}", "cmd"),
		"fileserve.hint.setcap_alt":  e("alternativa más amplia, para un servidor propio que sí use el puerto bajo (esta app no): {cmd}", "broader alternative, for a server of your own that does use the low port (this app does not): {cmd}", "cmd"),
		"fileserve.hint.nft_remove":  e("(quitar al terminar: {cmd})", "(remove when done: {cmd})", "cmd"),
		"fileserve.hint.setcap_warn": e("(ADVERTENCIA: ese binario podrá abrir cualquier puerto menor a 1024 mientras conserve el permiso; quitar: sudo setcap -r {bin})", "(WARNING: that binary will be able to open any port below 1024 while it keeps the permission; remove: sudo setcap -r {bin})", "bin"),
		"fileserve.hint.tftp_redir":  e("IOS siempre usa el puerto 69; redirígelo a este servidor (sin privilegios para la app):", "IOS always uses port 69; redirect it to this server (without privileges for the app):"),
	})
}
