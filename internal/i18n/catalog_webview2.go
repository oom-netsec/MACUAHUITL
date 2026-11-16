package i18n

// Textos de la app de escritorio en Windows que salen antes de la interfaz web (ui/bridge/webview2.go, ADR 0012).
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"ui.webview2_missing": e(
			"En este equipo no está instalado el runtime WebView2 de Microsoft, que MACUAHUITL necesita para su ventana. Descárgalo e instálalo desde {url} y vuelve a abrir MACUAHUITL.",
			"The Microsoft WebView2 Runtime is not installed on this computer, and MACUAHUITL needs it for its window. Download and install it from {url}, then open MACUAHUITL again.",
			"url"),
	})
}
