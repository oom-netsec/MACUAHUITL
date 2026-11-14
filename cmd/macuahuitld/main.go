// Command macuahuitld es el núcleo de MACUAHUITL: corre como servicio de usuario
// de systemd y atiende a la UI y a mctl por un socket Unix (spec §5).
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

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
	consoleLang = i18n.Normalize(*lang)
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "macuahuitld:", err)
		os.Exit(1)
	}
}

// consoleLang es el idioma de lo que el daemon imprime en su consola; sin --lang, el canónico (inglés).
var consoleLang = i18n.En

func run() error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("no corre como root (spec §2); usa systemctl --user")
	}
	hw := sys.Harden() // antes de tocar cualquier secreto
	warns := make([]string, len(hw))
	for i, w := range hw {
		warns[i] = w.In(i18n.En) // la auditoría va siempre en inglés
	}
	p := core.ResolvePaths(os.Getenv)
	if p.Runtime == "" {
		return fmt.Errorf("XDG_RUNTIME_DIR no está definido")
	}
	l, err := ipc.Listen(filepath.Join(p.Runtime, "core.sock"))
	if err != nil {
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
