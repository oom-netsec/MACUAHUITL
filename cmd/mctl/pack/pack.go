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

const help = `  pack install <archivo.mpack> [--allow-unsigned] [--hide ITEM]...  |  pack list  |  pack show <id>  |  pack remove <id>
        (paquetes de contenido: playbooks y scripts por tecnología; se bajan a mano de los releases y nada se descarga solo.
         Un paquete sin firma oficial es de terceros y solo se instala con --allow-unsigned; trae únicamente comandos de lectura.
         remove quita también los favoritos de sus scripts. show muestra el manifiesto y el README.
         --hide ITEM instala el paquete con ese playbook o script oculto, y se repite; con --hide, lo oculto queda
         exactamente en esos ITEM, y sin --hide una actualización conserva lo que ya estaba oculto)
  pack inspect <archivo.mpack> [--allow-unsigned]
        (vista previa de install: valida el paquete y muestra qué trae y qué reemplazaría, sin instalar nada)
  pack items <id> [--hide ITEM]... [--show ITEM]...
        (oculta o muestra playbooks y scripts de un paquete instalado: solo quita de las listas, el ID se sigue
         resolviendo y los trabajos lo pueden pedir; lo oculto sobrevive a las versiones nuevas y se borra con el paquete)`

func origin(p *v1.PackInfo) string {
	if p.Official {
		return cli.T("mctl.pack.official")
	}
	return cli.T("mctl.pack.third")
}

func line(p *v1.PackInfo) string {
	s := fmt.Sprintf("%s  %s  %s  %d playbooks  %d scripts  %s", p.Id, p.Version, origin(p), p.PlaybookCount, p.ScriptCount, p.Name)
	if len(p.Hidden) > 0 {
		s += cli.T("mctl.pack.hidden_n", "n", len(p.Hidden))
	}
	if len(p.Shadowed) > 0 {
		s += cli.T("mctl.pack.shadowed", "list", strings.Join(p.Shadowed, ", "))
	}
	return s
}

func install(c *cli.Env, args []string) error {
	var unsigned bool
	var hide multi
	fs, err := cli.Flags("pack install", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&unsigned, "allow-unsigned", false, "instala un paquete de terceros (sin firma oficial)")
		fs.Var(&hide, "hide", "ID de playbook o script que queda oculto (se repite)")
	})
	if err != nil || fs.NArg() != 1 {
		return errors.New("uso: mctl pack install <archivo.mpack> [--allow-unsigned] [--hide ITEM ...]")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := v1.NewPackServiceClient(c.Conn).Install(context.Background(), &v1.PackServiceInstallRequest{Path: path, AllowUnsigned: unsigned, Hide: hide, ReplaceHidden: len(hide) > 0})
	if err != nil {
		return err
	}
	verb := cli.T("mctl.pack.installed")
	if r.ReplacedVersion != "" {
		verb = cli.T("mctl.pack.updated", "version", r.ReplacedVersion)
	}
	fmt.Fprintf(c.Out, "%s: %s\n", verb, line(r.Pack))
	return nil
}

func inspect(c *cli.Env, args []string) error {
	var unsigned bool
	fs, err := cli.Flags("pack inspect", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&unsigned, "allow-unsigned", false, "acepta un paquete de terceros (sin firma oficial)")
	})
	if err != nil || fs.NArg() != 1 {
		return errors.New("uso: mctl pack inspect <archivo.mpack> [--allow-unsigned]")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := v1.NewPackServiceClient(c.Conn).Inspect(context.Background(), &v1.PackServiceInspectRequest{Path: path, AllowUnsigned: unsigned})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "%s\n", line(r.Pack))
	if r.ReplacedVersion != "" {
		fmt.Fprintln(c.Out, cli.T("mctl.pack.replaces", "version", r.ReplacedVersion))
	}
	fmt.Fprintf(c.Out, "playbooks:\n  %s\nscripts:\n  %s\n", strings.Join(r.PlaybookIds, "\n  "), strings.Join(r.ScriptIds, "\n  "))
	return nil
}

// multi es un flag que se repite.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func items(c *cli.Env, args []string) error {
	var hide, show multi
	fs, err := cli.Flags("pack items", args, func(fs *flag.FlagSet) {
		fs.Var(&hide, "hide", "ID de playbook o script que se oculta (se repite)")
		fs.Var(&show, "show", "ID de playbook o script que se vuelve a mostrar (se repite)")
	})
	if err != nil || fs.NArg() != 1 || len(hide)+len(show) == 0 {
		return errors.New("uso: mctl pack items <id> [--hide ITEM ...] [--show ITEM ...]")
	}
	r, err := v1.NewPackServiceClient(c.Conn).SetItems(context.Background(), &v1.PackServiceSetItemsRequest{PackId: fs.Arg(0), Hide: hide, Show: show})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "%s\n%s\n", line(r.Pack), cli.T("mctl.pack.hidden", "list", strings.Join(r.Pack.Hidden, ", ")))
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
		fmt.Fprintln(c.Out, cli.T("mctl.pack.none"))
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
	fmt.Fprintln(c.Out, cli.T("mctl.pack.show", "id", p.Id, "version", p.Version, "origin", origin(p), "min_core", p.MinCore, "name", p.Name, "description", p.Description,
		"platforms", strings.Join(p.Platforms, ", "), "author", p.Author, "license", p.License, "playbooks", len(r.PlaybookIds), "scripts", len(r.ScriptIds), "readme", r.Readme))
	if len(p.Hidden) > 0 {
		fmt.Fprintf(c.Out, "\n%s\n", cli.T("mctl.pack.hidden", "list", strings.Join(p.Hidden, ", ")))
	}
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
	fmt.Fprintln(c.Out, cli.T("mctl.pack.removed", "id", args[0], "n", r.FavoritesRemoved))
	return nil
}

// Area registra pack install, list, show y remove.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "pack install", Run: install}, {Name: "pack list", Run: list},
		{Name: "pack show", Run: show}, {Name: "pack remove", Run: remove}, {Name: "pack items", Run: items}, {Name: "pack inspect", Run: inspect}}}
}
