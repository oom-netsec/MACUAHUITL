// Package pack es el área de mctl para los paquetes de contenido (.mpack, fase 32, ADR 0010): instala desde un
// archivo local, lista, muestra y quita. mctl nunca descarga paquetes.
package pack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"

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
         resolviendo y los trabajos lo pueden pedir; lo oculto sobrevive a las versiones nuevas y se borra con el paquete)
  pack export <editor/nombre> [ID...] --out <archivo.mpack> [--playbooks] [--license SPDX] [--name N] [--description D] [--author A] [--overwrite]
        (arma un paquete personal SIN firma con los scripts del usuario ID... y, con --playbooks, los de <config>/playbooks de ios, ios-xe y wlc-9800.
         Los scripts salen como lib-<editor>-… y los playbooks con el editor como prefijo; los demás playbooks se omiten y se avisa. El editor es
         [a-z0-9]{1,16}, sin los reservados. Versión AAAA.MMDD.HHMMSS (hora local); licencia NOASSERTION si no das otra; los favoritos no viajan)
  pack import <archivo.mpack> [--decision ID=renombrar|omitir]... [--all=renombrar|omitir] [--preview]
        (copia un .mpack sin firma oficial a «Mis scripts» y a <config>/playbooks, editables, sin instalarlo. Muestra el estado de cada elemento:
         nuevo, igual, conflicto_id o conflicto_nombre; cada conflicto pide decisión y nunca se sobrescribe nada. Un playbook importado conserva su ID con
         prefijo de editor y entra al catálogo sin reiniciar)`

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

// fileSHA256 es la suma del archivo que mctl va a pedir instalar: el núcleo la compara con la del archivo que lee.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
	sum, err := fileSHA256(path)
	if err != nil {
		return err
	}
	r, err := v1.NewPackServiceClient(c.Conn).Install(context.Background(), &v1.PackServiceInstallRequest{Path: path, AllowUnsigned: unsigned, Hide: hide, ReplaceHidden: len(hide) > 0, Sha256: sum})
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

func exportCmd(c *cli.Env, args []string) error {
	var out, license, name, desc, author string
	var pbs, ow bool
	fs, err := cli.Flags("pack export", args, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "out", "", "archivo .mpack de salida")
		fs.BoolVar(&pbs, "playbooks", false, "incluye los playbooks de <config>/playbooks")
		fs.StringVar(&license, "license", "", "licencia SPDX (por omisión NOASSERTION)")
		fs.StringVar(&name, "name", "", "nombre del paquete")
		fs.StringVar(&desc, "description", "", "descripción del paquete")
		fs.StringVar(&author, "author", "", "autor (por omisión el editor)")
		fs.BoolVar(&ow, "overwrite", false, "reemplaza el archivo si existe")
	})
	const uso = "uso: mctl pack export <editor/nombre> [ID...] --out <archivo.mpack> [--playbooks] [--license SPDX] [--name N] [--description D] [--author A] [--overwrite]"
	if err != nil || out == "" || fs.NArg() < 1 || fs.NArg() == 1 && !pbs {
		return errors.New(uso)
	}
	if out, err = filepath.Abs(out); err != nil {
		return err
	}
	r, err := v1.NewPackServiceClient(c.Conn).Export(context.Background(), &v1.PackServiceExportRequest{EditorName: fs.Arg(0), ScriptIds: fs.Args()[1:],
		IncludePlaybooks: pbs, License: license, Path: out, Overwrite: ow, Name: name, Description: desc, Author: author})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "exportado %s %s: %d scripts, %d playbooks, sin firma, a %s\nsha256 %s\n", r.Id, r.Version, r.Scripts, r.Playbooks, out, r.Sha256)
	for _, id := range r.OmittedPlaybooks {
		fmt.Fprintf(c.Out, "aviso: el playbook %s no se exportó (plataforma o ID que un paquete no acepta)\n", id)
	}
	return nil
}

func importCmd(c *cli.Env, args []string) error {
	var decs cli.List
	var all string
	var preview bool
	fs, err := cli.Flags("pack import", args, func(fs *flag.FlagSet) {
		fs.Var(&decs, "decision", "ID=acción para un conflicto (repetible)")
		fs.StringVar(&all, "all", "", "acción para los conflictos sin --decision")
		fs.BoolVar(&preview, "preview", false, "solo la vista previa")
	})
	const uso = "uso: mctl pack import <archivo.mpack> [--decision ID=renombrar|omitir]... [--all=renombrar|omitir] [--preview]"
	if err != nil || fs.NArg() != 1 {
		return errors.New(uso)
	}
	dec := map[string]string{}
	for _, d := range decs {
		id, a, ok := strings.Cut(d, "=")
		if !ok || id == "" || (a != "renombrar" && a != "omitir") {
			return errors.New("decisión inválida " + strconv.Quote(d) + ": " + uso)
		}
		dec[id] = a
	}
	if all != "" && all != "renombrar" && all != "omitir" {
		return errors.New(uso)
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	cl := v1.NewPackServiceClient(c.Conn)
	pv, err := cl.Import(context.Background(), &v1.PackServiceImportRequest{Path: path})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIPO\tID\tNOMBRE\tESTADO\tCHOCA CON")
	var req []*v1.PackImportDecision
	var missing []string
	for _, it := range pv.Items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", it.Kind, it.Id, it.Name, it.State, it.ConflictsWith)
		a, ok := dec[it.Id]
		if !ok && (it.State == "conflicto_id" || it.State == "conflicto_nombre") {
			if a = all; a == "" {
				missing = append(missing, it.Id)
				continue
			}
			ok = true
		}
		if ok {
			req = append(req, &v1.PackImportDecision{ItemId: it.Id, Action: a})
		}
	}
	tw.Flush()
	known := map[string]bool{}
	for _, it := range pv.Items {
		known[it.Id] = true
	}
	for id := range dec {
		if !known[id] {
			return fmt.Errorf("la decisión nombra %q, que no está en el paquete", id)
		}
	}
	if preview {
		return nil
	}
	if len(missing) > 0 {
		return fmt.Errorf("no se importó nada: falta decidir %d conflicto(s); use --decision ID=renombrar|omitir o --all=ACCIÓN: %s", len(missing), strings.Join(missing, ", "))
	}
	r, err := cl.Import(context.Background(), &v1.PackServiceImportRequest{Path: path, Confirm: true, Decisions: req, Sha256: pv.Sha256})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "importados: scripts %d nuevos, %d renombrados, %d omitidos; playbooks %d nuevos, %d renombrados, %d omitidos\n",
		r.ScriptsCreated, r.ScriptsRenamed, r.ScriptsSkipped, r.PlaybooksCreated, r.PlaybooksRenamed, r.PlaybooksSkipped)
	return nil
}

// Area registra pack install, list, show, remove, export e import.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "pack install", Run: install}, {Name: "pack list", Run: list},
		{Name: "pack show", Run: show}, {Name: "pack remove", Run: remove}, {Name: "pack items", Run: items}, {Name: "pack inspect", Run: inspect},
		{Name: "pack export", Run: exportCmd}, {Name: "pack import", Run: importCmd}}}
}
