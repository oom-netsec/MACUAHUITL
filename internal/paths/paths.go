// Package paths resuelve las rutas del núcleo (spec §14; en Windows, ADR 0012). Es una hoja: solo usa la biblioteca
// estándar, para que la UI calcule las mismas rutas sin importar internal/core.
package paths

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

// Resolve sigue la especificación XDG (en Windows, ADR 0012); env suele ser os.Getenv.
func Resolve(env func(string) string) Paths {
	if runtime.GOOS == "windows" {
		return resolvePathsWindows(env)
	}
	home := env("HOME")
	if !filepath.IsAbs(home) { // vacío o relativo: las rutas saldrían relativas al directorio actual; quedan vacías y el núcleo no arranca
		home = ""
	}
	xdg := func(key, def string) string {
		if v := env(key); filepath.IsAbs(v) {
			return filepath.Join(v, "macuahuitl")
		}
		if def == "" || home == "" {
			return ""
		}
		return filepath.Join(home, def, "macuahuitl")
	}
	outputs := ""
	if home != "" {
		outputs = filepath.Join(home, "MACUAHUITL", "outputs")
	}
	return Paths{
		Config:  xdg("XDG_CONFIG_HOME", ".config"),
		Data:    xdg("XDG_DATA_HOME", ".local/share"),
		State:   xdg("XDG_STATE_HOME", ".local/state"),
		Runtime: xdg("XDG_RUNTIME_DIR", ""),
		Outputs: outputs,
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

// winAbs acepta solo la forma «X:\…» y devuelve la ruta sin barra final. Rechaza UNC, «\\?\», «\\.\», «//», barras
// dobles y cualquier elemento «..». Va a mano porque filepath.IsAbs depende del sistema donde corre la prueba.
func winAbs(s string) (string, bool) {
	if len(s) < 3 || !(s[0]|0x20 >= 'a' && s[0]|0x20 <= 'z') || s[1] != ':' || s[2] != '\\' {
		return "", false
	}
	if strings.Contains(s, "/") || strings.Contains(s[3:], `\\`) {
		return "", false
	}
	for _, e := range strings.Split(s[3:], `\`) {
		if e == ".." {
			return "", false
		}
	}
	if s = strings.TrimRight(s, `\`); len(s) == 2 { // «C:\» sin más
		return "", false
	}
	return s, true
}
