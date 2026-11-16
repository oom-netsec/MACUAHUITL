//go:build wails && windows

package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/oom-netsec/MACUAHUITL/internal/paths"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// redirectLog manda el registro de la app a <State>\macuahuitl.log, con la misma rotación y ACL que el del núcleo
// (sys.RedirectStderr): compilada con -H windowsgui no tiene consola y sin esto los errores (arranque del núcleo bajo
// demanda, NoDump, pánicos de Wails) se perderían. Va después de checkElevated: elevada, la app sale sin escribir nada.
// Sin State (LOCALAPPDATA inválida) no hay dónde y se sigue sin registro, como el núcleo, que tampoco arrancaría.
func redirectLog() {
	st := paths.Resolve(os.Getenv).State
	if st == "" {
		return
	}
	if err := sys.RedirectStderr(filepath.Join(st, "macuahuitl.log")); err == nil {
		log.SetOutput(os.Stderr) // el logger estándar guardó el os.Stderr del arranque, que en windowsgui no lleva a nada
	}
}
