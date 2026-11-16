//go:build wails && windows

package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/ui/bridge"
)

// coreLauncher arranca el núcleo bajo demanda (ADR 0012 (g)): no hay servicio, y la entrada Run solo lo lanza al iniciar
// sesión. La sonda es la del pipe (ipc.CoreRunning, vuelve en menos de 1 s) y el núcleo es el macuahuitld.exe de la
// carpeta de este ejecutable, nunca uno del PATH; sys.StartDetached lo lanza separado de la app.
func coreLauncher() *bridge.CoreLauncher {
	exe, err := os.Executable()
	if err != nil {
		log.Println("macuahuitl: sin arranque del núcleo bajo demanda:", err)
		return nil
	}
	// El exe puede ser un enlace (winget lo instala en Links\ apuntando a Packages\): se sigue para hallar el núcleo de al
	// lado, pero solo si conserva la letra de unidad; un enlace a \\srv\… o a \\?\Volume{…} lo rechazaría StartDetached.
	if real, err := filepath.EvalSymlinks(exe); err == nil && len(filepath.VolumeName(real)) == 2 {
		exe = real
	}
	core := filepath.Join(filepath.Dir(exe), "macuahuitld.exe")
	return &bridge.CoreLauncher{
		Running: ipc.CoreRunning,
		Start:   func() error { return sys.StartDetached(core) },
		Log:     func(err error) { log.Println("macuahuitl: núcleo:", i18n.English(err)) }, // en inglés si trae código del catálogo
	}
}
