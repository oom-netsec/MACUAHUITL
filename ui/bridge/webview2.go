package bridge

import (
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Aviso de WebView2 faltante en Windows (ui/webview2_windows.go, ADR 0012). Sin el runtime, Wails sale con os.Exit(1) y
// el error va a stderr, que una app GUI de Windows no tiene: la app revisa antes de abrir la ventana. La lógica vive aquí
// para probarse en Linux; leer el registro y mostrar el MessageBox es lo único propio de Windows.

// WebView2DownloadURL es la página oficial de descarga del runtime (Evergreen, con el instalador sin conexión).
const WebView2DownloadURL = "https://developer.microsoft.com/microsoft-edge/webview2/consumer/"

// WebView2Missing dice si falta el runtime según los valores «pv» de HKLM y HKCU: vacío o 0.0.0.0 es «no instalado», y
// basta uno con versión (Microsoft, «Detect if a WebView2 Runtime is already installed»).
func WebView2Missing(pv ...string) bool {
	for _, v := range pv {
		if v = strings.TrimSpace(v); v != "" && v != "0.0.0.0" {
			return false
		}
	}
	return true
}

// WebView2MissingText es el mensaje en los dos idiomas, inglés primero: al arrancar aún no se sabe cuál eligió el usuario.
func WebView2MissingText() string {
	a := i18n.A("url", WebView2DownloadURL)
	return i18n.Msg(i18n.En, "ui.webview2_missing", a) + "\n\n" + i18n.Msg(i18n.Es, "ui.webview2_missing", a)
}
