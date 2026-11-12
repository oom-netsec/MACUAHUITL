// Package core arranca el núcleo, controla su ciclo de vida y conecta los
// servicios entre sí.
//
// No hace: lógica de negocio; solo cableado.
package core

import "path/filepath"

// Paths son las rutas de spec §14. Runtime vacío significa que no hay XDG_RUNTIME_DIR.
type Paths struct {
	Config, Data, State, Runtime, Outputs string
	Home                                  string // carpeta personal; vacía en pruebas
}

// ResolvePaths sigue la especificación XDG; env suele ser os.Getenv.
func ResolvePaths(env func(string) string) Paths {
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
