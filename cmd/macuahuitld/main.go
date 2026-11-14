// Command macuahuitld es el núcleo de MACUAHUITL: corre como servicio de usuario
// de systemd y atiende a la UI y a mctl por un socket Unix (spec §5).
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "macuahuitld:", err)
		os.Exit(1)
	}
}

// consoleLang es el idioma de lo que el daemon imprime en su consola; sin --lang, el canónico (inglés).
var consoleLang = i18n.En

func run() error {
	if os.Geteuid() == 0 {
		return errors.New(i18n.Msg(consoleLang, "harden.err.root", nil))
	}
	hw := sys.Harden() // antes de tocar cualquier secreto
	warns := make([]string, len(hw))
	for i, w := range hw {
		warns[i] = w.In(i18n.En) // la auditoría va siempre en inglés
	}
	p := core.ResolvePaths(os.Getenv)
	if p.Runtime == "" {
		return errors.New(i18n.Msg(consoleLang, "harden.err.runtime_dir", nil))
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
