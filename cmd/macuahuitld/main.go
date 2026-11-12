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
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/internal/version"
)

func main() {
	showVersion := flag.Bool("version", false, "imprime la versión y sale")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String())
		return
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "macuahuitld:", err)
		os.Exit(1)
	}
}

func run() error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("no corre como root (spec §2); usa systemctl --user")
	}
	warns := sys.Harden() // antes de tocar cualquier secreto
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
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "aviso:", w)
	}
	return c.Serve(ctx, l)
}
