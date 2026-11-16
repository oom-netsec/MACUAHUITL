package i18n

// Textos de las pistas de puertos en Windows (ADR 0012 h): ahí no hay puertos privilegiados ni nftables ni setcap;
// lo que hace falta es una regla de entrada del Firewall de Windows que el usuario corre él mismo. El llamador
// (internal/diag/fileserve) elige estos códigos por sistema; los comandos de PowerShell y las IP son datos.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"fileserve.hint.win_std_port":   e("IOS usa el puerto {std} de {proto}; escucho en el {port}. En Windows no hay puertos privilegiados, pero el Firewall de Windows debe dejar entrar el tráfico:", "IOS uses port {std} for {proto}; I listen on {port}. Windows has no privileged ports, but Windows Firewall must let the traffic in:", "std", "proto", "port"),
		"fileserve.hint.win_redirect":   e("regla de entrada del firewall (PowerShell como administrador, una vez; la app nunca la aplica; también sirve aceptar el diálogo del firewall): {cmd}", "inbound firewall rule (PowerShell as administrator, once; the app never applies it; accepting the firewall dialog also works): {cmd}", "cmd"),
		"fileserve.hint.win_tftp_redir": e("IOS siempre usa el puerto 69; en Windows se escucha ahí directo y solo hace falta esta regla de firewall (PowerShell como administrador):", "IOS always uses port 69; on Windows the server listens there directly and only this firewall rule is needed (PowerShell as administrator):"),
	})
}
