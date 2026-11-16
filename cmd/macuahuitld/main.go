// Command macuahuitld es el núcleo de MACUAHUITL: corre como servicio de usuario
// de systemd (en Windows, lanzado por el usuario) y atiende a la UI y a mctl por un socket Unix o un named pipe (spec §5).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/core"
	"github.com/oom-netsec/MACUAHUITL/internal/core/power"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "imprime la versión y sale")
	lang := flag.String("lang", "", "idioma de los avisos de la consola: en (por omisión) o es")
	flag.Parse()
	l, err := parseLang(*lang)
	if err != nil {
		fmt.Fprintln(os.Stderr, "macuahuitld:", err)
		os.Exit(2)
	}
	consoleLang = l
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	if err := run(sys.Harden); err != nil {
		fmt.Fprintln(os.Stderr, "macuahuitld:", err)
		os.Exit(1)
	}
}

// consoleLang es el idioma de lo que el daemon imprime en su consola; sin --lang, el canónico (inglés).
var consoleLang = i18n.En

// run recibe el endurecimiento como dependencia: en producción sys.Harden; las pruebas pasan una falsa (mlockall no va en go test).
func run(harden func() ([]i18n.Text, error)) error {
	if sys.Privileged() {
		key := "harden.err.root"
		if runtime.GOOS == "windows" {
			key = "harden.err.elevated"
		}
		return errors.New(i18n.Msg(consoleLang, key, nil))
	}
	hw, err := harden() // antes de tocar cualquier secreto
	if err != nil {
		return errors.New(i18n.In(consoleLang, err))
	}
	warns := make([]string, len(hw))
	for i, w := range hw {
		warns[i] = w.In(i18n.En) // la auditoría va siempre en inglés
	}
	p := core.ResolvePaths(os.Getenv)
	if p.Config == "" || p.Data == "" || p.State == "" {
		return errors.New(i18n.Msg(consoleLang, "harden.err.localappdata", nil)) // solo Windows: no se cae a %APPDATA%
	}
	if runtime.GOOS != "windows" && p.Runtime == "" { // en Windows no hay carpeta runtime: el canal es un named pipe
		return errors.New(i18n.Msg(consoleLang, "harden.err.runtime_dir", nil))
	}
	// El canal primero: un segundo núcleo que pierde el pipe (o el socket) sale sin tocar nada del primero, ni su registro.
	addr, err := ipc.CoreAddr(p.Runtime)
	if err != nil {
		return err
	}
	l, err := ipc.Listen(addr)
	if err != nil {
		return err
	}
	// Sin consola (-H windowsgui) la salida va a <State>\macuahuitld.log; en Linux no hace nada (stderr, journal).
	if err := sys.RedirectStderr(filepath.Join(p.State, "macuahuitld.log")); err != nil {
		l.Close()
		return err
	}
	c, err := core.New(p, core.Options{Inhibitor: power.NewLogind(), HardenWarnings: warns})
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, stop := sys.SignalContext()
	defer stop()
	go power.Watch(ctx, c.OnSleep, c.OnLock)
	for _, w := range hw {
		fmt.Fprintln(os.Stderr, consolePrefix(), w.In(consoleLang))
	}
	return c.Serve(ctx, l)
}

// consolePrefix es «warning:» o «aviso:» según el idioma de la consola.
func consolePrefix() string { return i18n.Msg(consoleLang, "harden.prefix", nil) }

// parseLang valida -lang: vacío es el canónico (inglés); es, en o una etiqueta es-MX/en-US. Otro valor es un error, no el
// idioma por omisión en silencio.
func parseLang(v string) (string, error) {
	if v == "" {
		return i18n.En, nil
	}
	t, n := strings.ToLower(strings.TrimSpace(v)), i18n.Normalize(v)
	if t != n && !strings.HasPrefix(t, n+"-") && !strings.HasPrefix(t, n+"_") {
		return "", fmt.Errorf("invalid -lang %q (use es or en)", v)
	}
	return n, nil
}
