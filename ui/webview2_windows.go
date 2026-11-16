//go:build wails && windows

package main

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/oom-netsec/MACUAHUITL/internal/paths"
	"github.com/oom-netsec/MACUAHUITL/ui/bridge"
)

// webView2Client es la clave del runtime Evergreen de WebView2 (Microsoft, «Detect if a WebView2 Runtime is already
// installed»): bajo HKLM\SOFTWARE\WOW6432Node para la instalación por equipo y bajo HKCU\Software para la de usuario.
const webView2Client = `Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`

// checkWebView2 sale con un MessageBox si falta WebView2: sin él, Wails cerraría la app sin ningún aviso visible.
// shortcut: solo mira el runtime estable (método 1 de Microsoft); Wails lo busca distinto (EBWebView en ClientState, también
// en Edge Beta/Dev/Canary). Un equipo con solo un canal de prueba recibe el aviso aunque Wails abriría, y un runtime roto
// con «pv» presente sigue cerrando sin aviso. Si aparece alguno, pasar un ErrorHandler a Wails en vez de revisar aquí.
func checkWebView2() {
	if !bridge.WebView2Missing(registryPV(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\`+webView2Client),
		registryPV(registry.CURRENT_USER, `Software\`+webView2Client)) {
		return
	}
	title, _ := windows.UTF16PtrFromString("MACUAHUITL")
	msg, _ := windows.UTF16PtrFromString(bridge.WebView2MissingText())
	_, _ = windows.MessageBox(0, msg, title, windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
	os.Exit(1)
}

// webviewUserDataPath es donde WebView2 guarda su perfil y su caché: dentro de State (ADR 0012), local y no roaming.
// Por omisión Wails usaría %APPDATA%\macuahuitl.exe, que en un dominio viaja con el perfil.
// La misma regla de rutas que el núcleo (internal/paths): si State sale vacía, el núcleo tampoco arranca y no se fija
// nada (queda el valor de Wails; la app ya muestra el error de conexión).
func webviewUserDataPath() string {
	if st := paths.Resolve(os.Getenv).State; st != "" {
		return filepath.Join(st, "webview2")
	}
	return ""
}

// registryPV lee el valor «pv» de la clave; vacío si la clave o el valor no existen.
func registryPV(root registry.Key, path string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, _ := k.GetStringValue("pv")
	return v
}
