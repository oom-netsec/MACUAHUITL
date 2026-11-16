package i18n

// Textos de la app de escritorio en Windows que salen antes de la interfaz web (ui/bridge/webview2.go, ADR 0012).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"ui.err.applog": e(
			"MACUAHUITL no pudo abrir su registro en {path}: {err}. Sigue sin registro; si el núcleo tampoco arranca, revisa los permisos de esa carpeta.",
			"MACUAHUITL could not open its log at {path}: {err}. It continues without a log; if the core does not start either, check that folder's permissions.",
			"path", "err"),
		"ui.err.elevated": e(
			"MACUAHUITL no corre elevado. Se abrió con «Ejecutar como administrador», o la cuenta tiene UAC desactivado o es el Administrador integrado, que siempre corren elevadas. Ábrelo de la forma normal; si este aviso sigue saliendo, usa una cuenta estándar o una de administrador con UAC activo.",
			"MACUAHUITL does not run elevated. It was started with «Run as administrator», or the account has UAC turned off or is the built-in Administrator, which always run elevated. Open it the normal way; if this message keeps appearing, use a standard account or an administrator account with UAC on."),
		"ui.webview2_missing": e(
			"En este equipo no está instalado el runtime WebView2 de Microsoft, que MACUAHUITL necesita para su ventana. Descárgalo e instálalo desde {url} y vuelve a abrir MACUAHUITL.",
			"The Microsoft WebView2 Runtime is not installed on this computer, and MACUAHUITL needs it for its window. Download and install it from {url}, then open MACUAHUITL again.",
			"url"),
	})
}
