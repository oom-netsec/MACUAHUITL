//go:build wails && windows

package main

import (
	"os"

	"golang.org/x/sys/windows"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/ui/bridge"
)

// checkElevated sale con un MessageBox si la app corre elevada: el núcleo que lanzaría (o el de la entrada Run) se niega
// a correr así, y sin esto la app solo mostraría «desconectado» sin decir por qué (hallazgo en Windows 11 real).
func checkElevated() {
	if !sys.Privileged() {
		return
	}
	title, _ := windows.UTF16PtrFromString("MACUAHUITL")
	msg, _ := windows.UTF16PtrFromString(bridge.ElevatedText())
	_, _ = windows.MessageBox(0, msg, title, windows.MB_OK|windows.MB_ICONERROR|windows.MB_SETFOREGROUND)
	os.Exit(1)
}
