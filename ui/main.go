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
	"log/slog"
	"os"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
	checkWebView2() // Windows: sin WebView2, aviso y salida antes de que Wails cierre la app sin decir nada
	checkElevated() // Windows: elevada, el núcleo se negaría; aviso y salida en vez de «desconectado» sin causa
	// La contraseña maestra y las credenciales pasan por el puente: sin volcados de memoria si la UI se cae.
	for _, w := range sys.NoDump() {
		log.Println("macuahuitl:", w.In(i18n.En))
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
		// Con la etiqueta production Wails descarta su registro: sin esto, un pánico cerraría la ventana sin rastro.
		// Solo avisos y errores, a stderr (el journal de la sesión).
		Logger: slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
		// Wayland toma el app_id de este nombre y GNOME busca macuahuitl.desktop con él para el ícono del dock;
		// fijo para que no dependa del nombre del ejecutable.
		Linux:    application.LinuxOptions{ProgramName: "macuahuitl"},
		Windows:  application.WindowsOptions{WebviewUserDataPath: webviewUserDataPath()},
		Services: []application.Service{application.NewService(b)},
		Assets:   application.AssetOptions{Handler: application.AssetFileServerFS(dist)},
	})
	// Sin marco: la UI dibuja sus propios controles y zonas de arrastre (ui/frontend/src/app).
	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title: "MACUAHUITL", Width: bridge.WindowWidth, Height: bridge.WindowHeight, MinWidth: bridge.WindowMinWidth, MinHeight: bridge.WindowMinHeight, Frameless: true,
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
	// Cerrar (✕ propio, Alt+F4, la barra de tareas) con sesiones o tareas en curso pregunta antes: se cortarían sin aviso
	// y un cambio asistido quedaría esperando en el núcleo. El hook no debe bloquear el despachador de eventos: Busy (toma
	// el candado del puente), el idioma y el diálogo van en otra goroutine. quitting se enciende justo antes del cierre
	// real: un segundo ✕ durante la espera no se salta la escritura final.
	var quitting, asking atomic.Bool
	win.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if quitting.Load() {
			return
		}
		e.Cancel()
		// shortcut: si GTK devolviera una respuesta que no mapea a ningún botón, asking quedaría encendido y el ✕ ya no
		// preguntaría (ni cerraría); Esc y la ✕ del diálogo sí mapean a Cancelar. Revisar si se cambia de versión de Wails.
		if !asking.CompareAndSwap(false, true) {
			return // ya hay un aviso abierto
		}
		go func() {
			if !bridge.Busy(b) {
				quitting.Store(true)
				win.Close()
				return
			}
			t := bridge.CloseTextFor(b)
			d := app.Dialog.Question().SetTitle(t.Title).SetMessage(t.Message).AttachToWindow(win)
			d.AddButton(t.Quit).OnClick(func() { // Wails ya corre OnClick en su propia goroutine
				app.Event.Emit("ui:closing", nil) // la terminal hace su última escritura del registro
				time.Sleep(700 * time.Millisecond)
				quitting.Store(true)
				win.Close()
			})
			stay := d.AddButton(t.Stay).OnClick(func() { asking.Store(false) })
			d.SetDefaultButton(stay)
			d.SetCancelButton(stay)
			d.Show()
		}()
	})
	// En una pantalla chica (1366×768) el tamaño preferido deja la barra de estado fuera: al arrancar se ajusta al 90 %
	// del área de trabajo de la pantalla, sin bajar del mínimo, y se centra en ella. El área de trabajo real (sin paneles)
	// es la de la pantalla principal; si su caché aún no está, la geometría completa de la pantalla de la ventana.
	// Wails ya corre cada escucha en su propia goroutine (con recuperación de pánicos).
	app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		s := app.Screen.GetPrimary()
		if s == nil {
			s, _ = win.GetScreen()
		}
		if s == nil {
			return
		}
		wa := s.WorkArea
		if w, h := bridge.InitialSize(wa.Width, wa.Height); w != bridge.WindowWidth || h != bridge.WindowHeight {
			win.SetSize(w, h)
			// Center usaría el tamaño que GTK reporta antes de aplicar SetSize: la posición se calcula con el nuevo.
			win.SetRelativePosition(wa.X-s.Bounds.X+max(0, (wa.Width-w)/2), wa.Y-s.Bounds.Y+max(0, (wa.Height-h)/2))
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridge.Start(ctx, b)
	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
