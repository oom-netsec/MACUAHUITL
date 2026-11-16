//go:build wails && windows

package main

import (
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/oom-netsec/MACUAHUITL/internal/paths"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/ui/bridge"
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
	path := filepath.Join(st, "macuahuitl.log")
	if err := sys.RedirectStderr(path); err != nil {
		// Sin consola no hay otro lugar donde decirlo; se avisa y se sigue (el núcleo dirá lo suyo si tampoco puede).
		title, _ := windows.UTF16PtrFromString("MACUAHUITL")
		msg, _ := windows.UTF16PtrFromString(bridge.AppLogText(path, err))
		_, _ = windows.MessageBox(0, msg, title, windows.MB_OK|windows.MB_ICONWARNING|windows.MB_SETFOREGROUND)
		return
	}
	log.SetOutput(os.Stderr) // el logger estándar guardó el os.Stderr del arranque, que en windowsgui no lleva a nada
}
