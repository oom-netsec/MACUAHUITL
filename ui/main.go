//go:build wails

// Command macuahuitl es la UI de escritorio (Wails v3). Solo es cliente del núcleo:
// no tiene bóveda, red ni almacenamiento propios (spec §5).
//
// Se compila con: go build -tags wails ./ui (requiere WebKitGTK; ver deploy/packaging).
package main

import (
	"context"
	"embed"
	"io/fs"
	"log"
	"os"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/ui/bridge"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed icon.png
var icon []byte

// coreLocalize es la bandera core.localize: con true el puente manda el idioma de la interfaz (preferencia ui.language) en
// accept-language y el núcleo contesta en ese idioma. Encendida: la interfaz usa reason/metadata y manda ui.language;
// MACUAHUITL_CORE_LOCALIZE=1 sigue forzándola por si se vuelve a apagar la constante.
const coreLocalize = true

func main() {
	// La contraseña maestra y las credenciales pasan por el puente: sin volcados de memoria si la UI se cae.
	for _, w := range sys.NoDump() {
		log.Println("macuahuitl:", w)
	}
	dist, err := fs.Sub(assets, "frontend/dist")
	if err != nil {
		log.Fatal(err)
	}
	var app *application.App
	b := bridge.New(func() (*ipc.ClientConn, error) { return ipc.Dial(context.Background()) },
		func(name string, data any) { app.Event.Emit(name, data) })
	b.Localize = coreLocalize || os.Getenv("MACUAHUITL_CORE_LOCALIZE") == "1"
	app = application.New(application.Options{
		Name: "MACUAHUITL",
		Icon: icon,
		// Wayland toma el app_id de este nombre y GNOME busca macuahuitl.desktop con él para el ícono del dock;
		// fijo para que no dependa del nombre del ejecutable.
		Linux:    application.LinuxOptions{ProgramName: "macuahuitl"},
		Services: []application.Service{application.NewService(b)},
		Assets:   application.AssetOptions{Handler: application.AssetFileServerFS(dist)},
	})
	// Sin marco: la UI dibuja sus propios controles y zonas de arrastre (ui/frontend/src/app).
	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title: "MACUAHUITL", Width: 1280, Height: 800, MinWidth: 960, MinHeight: 640, Frameless: true,
		Linux: application.LinuxWindow{Icon: icon}, EnableFileDrop: true,
	})
	// Archivos soltados sobre una zona [data-file-drop-target]: la UI recibe las rutas y el id de la zona.
	// Solo rutas: leer o subir el archivo sigue pasando por el núcleo como cualquier ruta escrita a mano.
	win.OnWindowEvent(events.Common.WindowFilesDropped, func(e *application.WindowEvent) {
		target := ""
		if d := e.Context().DropTargetDetails(); d != nil {
			target = d.ElementID
		}
		app.Event.Emit("ui:files-dropped", map[string]any{"target": target, "paths": e.Context().DroppedFiles()})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge.Start(ctx, b)
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
