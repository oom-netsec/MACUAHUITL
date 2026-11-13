// Package pack es el área de mctl para los paquetes de contenido (.mpack, fase 32, ADR 0010): instala desde un
// archivo local, lista, muestra y quita. mctl nunca descarga paquetes.
package pack

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const help = `  pack install <archivo.mpack> [--allow-unsigned]  |  pack list  |  pack show <id>  |  pack remove <id>
        (paquetes de contenido: playbooks y scripts por tecnología; se bajan a mano de los releases y nada se descarga solo.
         Un paquete sin firma oficial es de terceros y solo se instala con --allow-unsigned; trae únicamente comandos de lectura.
         remove quita también los favoritos de sus scripts. show muestra el manifiesto y el README)`

func origin(p *v1.PackInfo) string {
	if p.Official {
		return "oficial"
	}
	return "terceros"
}

func line(p *v1.PackInfo) string {
	s := fmt.Sprintf("%s  %s  %s  %d playbooks  %d scripts  %s", p.Id, p.Version, origin(p), p.PlaybookCount, p.ScriptCount, p.Name)
	if len(p.Shadowed) > 0 {
		s += "  (tapados por los tuyos: " + strings.Join(p.Shadowed, ", ") + ")"
	}
	return s
}

func install(c *cli.Env, args []string) error {
	var unsigned bool
	fs, err := cli.Flags("pack install", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&unsigned, "allow-unsigned", false, "instala un paquete de terceros (sin firma oficial)")
	})
	if err != nil || fs.NArg() != 1 {
		return errors.New("uso: mctl pack install <archivo.mpack> [--allow-unsigned]")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := v1.NewPackServiceClient(c.Conn).Install(context.Background(), &v1.PackServiceInstallRequest{Path: path, AllowUnsigned: unsigned})
	if err != nil {
		return err
	}
	verb := "instalado"
	if r.ReplacedVersion != "" {
		verb = "actualizado (antes " + r.ReplacedVersion + ")"
	}
	fmt.Fprintf(c.Out, "%s: %s\n", verb, line(r.Pack))
	return nil
}

func list(c *cli.Env, args []string) error {
	if len(args) != 0 {
		return errors.New("uso: mctl pack list")
	}
	r, err := v1.NewPackServiceClient(c.Conn).List(context.Background(), &v1.PackServiceListRequest{})
	if err != nil {
		return err
	}
	if len(r.Packs) == 0 {
		fmt.Fprintln(c.Out, "no hay paquetes instalados")
	}
	for _, p := range r.Packs {
		fmt.Fprintln(c.Out, line(p))
	}
	return nil
}

func show(c *cli.Env, args []string) error {
	if len(args) != 1 {
		return errors.New("uso: mctl pack show <id>")
	}
	r, err := v1.NewPackServiceClient(c.Conn).Show(context.Background(), &v1.PackServiceShowRequest{Id: args[0]})
	if err != nil {
		return err
	}
	p := r.Pack
	fmt.Fprintf(c.Out, "id: %s\nversión: %s\norigen: %s\nnúcleo mínimo: %s\nnombre: %s\ndescripción: %s\nplataformas: %s\nautor: %s\nlicencia: %s\nplaybooks: %d\nscripts: %d\n\n%s\n",
		p.Id, p.Version, origin(p), p.MinCore, p.Name, p.Description, strings.Join(p.Platforms, ", "), p.Author, p.License, len(r.PlaybookIds), len(r.ScriptIds), r.Readme)
	return nil
}

func remove(c *cli.Env, args []string) error {
	if len(args) != 1 {
		return errors.New("uso: mctl pack remove <id>")
	}
	r, err := v1.NewPackServiceClient(c.Conn).Remove(context.Background(), &v1.PackServiceRemoveRequest{Id: args[0]})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "quitado: %s (%d favoritos quitados)\n", args[0], r.FavoritesRemoved)
	return nil
}

// Area registra pack install, list, show y remove.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "pack install", Run: install}, {Name: "pack list", Run: list},
		{Name: "pack show", Run: show}, {Name: "pack remove", Run: remove}}}
}
