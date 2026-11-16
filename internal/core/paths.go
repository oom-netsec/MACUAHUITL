// Package core arranca el núcleo, controla su ciclo de vida y conecta los
// servicios entre sí.
//
// No hace: lógica de negocio; solo cableado.
package core

import (
	"path/filepath"
	"runtime"
	"strings"
)

// Paths son las rutas de spec §14. Runtime vacío significa que no hay XDG_RUNTIME_DIR.
type Paths struct {
	Config, Data, State, Runtime, Outputs string
	Home                                  string // carpeta personal; vacía en pruebas
}

// ResolvePaths sigue la especificación XDG (en Windows, ADR 0012); env suele ser os.Getenv.
func ResolvePaths(env func(string) string) Paths {
	if runtime.GOOS == "windows" {
		return resolvePathsWindows(env)
	}
	home := env("HOME")
	xdg := func(key, def string) string {
		if v := env(key); filepath.IsAbs(v) {
			return filepath.Join(v, "macuahuitl")
		}
		if def == "" {
			return ""
		}
		return filepath.Join(home, def, "macuahuitl")
	}
	return Paths{
		Config:  xdg("XDG_CONFIG_HOME", ".config"),
		Data:    xdg("XDG_DATA_HOME", ".local/share"),
		State:   xdg("XDG_STATE_HOME", ".local/state"),
		Runtime: xdg("XDG_RUNTIME_DIR", ""),
		Outputs: filepath.Join(home, "MACUAHUITL", "outputs"),
		Home:    home,
	}
}

// resolvePathsWindows pone todo bajo %LOCALAPPDATA%\MACUAHUITL (ADR 0012). Nunca %APPDATA%: es roaming y en un dominio
// subiría la bóveda y los paquetes a un servidor. Si LOCALAPPDATA no es absoluta, Config, Data y State quedan vacíos y
// el núcleo no arranca. No hay Runtime (el named pipe no lo necesita). Recibe env para probarse en cualquier sistema.
func resolvePathsWindows(env func(string) string) Paths {
	var p Paths
	if base, ok := winAbs(env("LOCALAPPDATA")); ok {
		p.Config, p.Data, p.State = base+`\MACUAHUITL\config`, base+`\MACUAHUITL\data`, base+`\MACUAHUITL\state`
	}
	if home, ok := winAbs(env("USERPROFILE")); ok {
		p.Home, p.Outputs = home, home+`\MACUAHUITL\outputs`
	}
	return p
}

// winAbs acepta «C:\…» (o con «/») y UNC, y devuelve la ruta con «\» y sin barra final. Va a mano porque
// filepath.IsAbs depende del sistema donde corre la prueba.
func winAbs(s string) (string, bool) {
	s = strings.ReplaceAll(s, "/", `\`)
	drive := len(s) >= 3 && (s[0]|0x20 >= 'a' && s[0]|0x20 <= 'z') && s[1] == ':' && s[2] == '\\'
	if !drive && !strings.HasPrefix(s, `\\`) {
		return "", false
	}
	if s = strings.TrimRight(s, `\`); len(s) == 2 { // «C:\» sin más
		return "", false
	}
	return s, true
}
