package scripts

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Colecciones de scripts y fijados (fase 29c).

const colUso = "uso: mctl scripts col list|show|add|edit|rm|set|order|export|import"

// col reparte «scripts col <sub>»: la tabla de comandos solo entiende dos palabras.
func col(c *cli.Env, args []string) error {
	if len(args) == 0 {
		return errors.New(colUso)
	}
	subs := map[string]func(*cli.Env, []string) error{"list": colList, "show": colShow, "add": colAdd, "edit": colEdit, "rm": colRm,
		"set": colSet, "order": colOrder, "export": colExport, "import": colImport}
	f, ok := subs[args[0]]
	if !ok {
		return errors.New(colUso)
	}
	return f(c, args[1:])
}

// scripts col list [--json]
func colList(c *cli.Env, args []string) error {
	var asJSON bool
	fs, err := cli.Flags("scripts col list", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "salida JSON") })
	if err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("uso: mctl scripts col list [--json]")
	}
	res, err := client(c).ListCollections(context.Background(), &v1.ListCollectionsRequest{})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(c, res)
	}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tORDEN\tNOMBRE\tSCRIPTS")
	for _, x := range res.Collections {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%d\n", x.Id, x.Order, x.Name, len(x.ScriptIds))
	}
	return tw.Flush()
}

// scripts col show ID [--json]
func colShow(c *cli.Env, args []string) error {
	var asJSON bool
	fs, err := cli.Flags("scripts col show", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "salida JSON") })
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl scripts col show ID [--json]")
	}
	cl := client(c)
	res, err := cl.GetCollection(context.Background(), &v1.GetCollectionRequest{Id: fs.Arg(0)})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(c, res)
	}
	x := res.Collection
	all, err := cl.ListScripts(context.Background(), &v1.ListScriptsRequest{})
	if err != nil {
		return err
	}
	names := map[string]string{}
	for _, s := range all.Scripts {
		names[s.Id] = s.Name
	}
	fmt.Fprintf(c.Out, "%s\n  id: %s · orden %d · %d scripts\n", x.Name, x.Id, x.Order, len(x.ScriptIds))
	if x.Description != "" {
		fmt.Fprintf(c.Out, "  %s\n", x.Description)
	}
	fmt.Fprintf(c.Out, "  creada: %s · editada: %s\n\n", ts(x.CreatedMs), ts(x.UpdatedMs))
	for i, id := range x.ScriptIds {
		fmt.Fprintf(c.Out, "%3d. %s  %s\n", i+1, id, names[id])
	}
	return nil
}

func colSaved(c *cli.Env, verb string, x *v1.Collection) {
	fmt.Fprintf(c.Out, "%s %s (%s)\n", verb, x.Id, x.Name)
}

// scripts col add NOMBRE [--desc D]
func colAdd(c *cli.Env, args []string) error {
	var desc string
	fs, err := cli.Flags("scripts col add", args, func(fs *flag.FlagSet) { fs.StringVar(&desc, "desc", "", "descripción") })
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl scripts col add NOMBRE [--desc D]")
	}
	r, err := client(c).SaveCollection(context.Background(), &v1.SaveCollectionRequest{Collection: &v1.Collection{Name: fs.Arg(0), Description: desc}})
	if err != nil {
		return err
	}
	colSaved(c, "creada", r.Collection)
	return nil
}

// scripts col edit ID [--name N] [--desc D]
func colEdit(c *cli.Env, args []string) error {
	var name, desc string
	fs, err := cli.Flags("scripts col edit", args, func(fs *flag.FlagSet) {
		fs.StringVar(&name, "name", "", "nombre")
		fs.StringVar(&desc, "desc", "", "descripción")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl scripts col edit ID [--name N] [--desc D]")
	}
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	cl := client(c)
	cur, err := cl.GetCollection(context.Background(), &v1.GetCollectionRequest{Id: fs.Arg(0)})
	if err != nil {
		return err
	}
	x := cur.Collection
	if set["name"] {
		x.Name = name
	}
	if set["desc"] {
		x.Description = desc
	}
	r, err := cl.SaveCollection(context.Background(), &v1.SaveCollectionRequest{Collection: x})
	if err != nil {
		return err
	}
	colSaved(c, "guardada", r.Collection)
	return nil
}

// scripts col rm ID
func colRm(c *cli.Env, args []string) error {
	id, err := cli.OneArg("scripts col rm", args)
	if err != nil {
		return err
	}
	if _, err := client(c).DeleteCollection(context.Background(), &v1.DeleteCollectionRequest{Id: id}); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "borrada %s\n", id)
	return nil
}

// scripts col set ID [SCRIPT_ID...] [--add ID]... [--rm ID]... [--clear]
// Con SCRIPT_ID deja exactamente esos y en ese orden; si no, parte de lo que hay (o de nada con --clear).
func colSet(c *cli.Env, args []string) error {
	var add, rm cli.List
	var clear bool
	fs, err := cli.Flags("scripts col set", args, func(fs *flag.FlagSet) {
		fs.Var(&add, "add", "agrega un script al final (repetible)")
		fs.Var(&rm, "rm", "quita un script (repetible)")
		fs.BoolVar(&clear, "clear", false, "vacía la colección")
	})
	if err != nil {
		return err
	}
	const uso = "uso: mctl scripts col set ID [SCRIPT_ID...] [--add ID]... [--rm ID]... [--clear]"
	if fs.NArg() < 1 || (fs.NArg() == 1 && len(add) == 0 && len(rm) == 0 && !clear) {
		return errors.New(uso)
	}
	cl := client(c)
	ids := []string{}
	if fs.NArg() > 1 {
		ids = fs.Args()[1:]
	} else if !clear {
		cur, err := cl.GetCollection(context.Background(), &v1.GetCollectionRequest{Id: fs.Arg(0)})
		if err != nil {
			return err
		}
		ids = cur.Collection.ScriptIds
	}
	ids = slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return slices.Contains(rm, id) })
	for _, id := range add {
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	r, err := cl.SetCollectionScripts(context.Background(), &v1.SetCollectionScriptsRequest{Id: fs.Arg(0), ScriptIds: ids})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "colección %s (%s): %d scripts\n", r.Collection.Id, r.Collection.Name, len(r.Collection.ScriptIds))
	return nil
}

// scripts col order ID...   (todas las colecciones, también favoritos)
func colOrder(c *cli.Env, args []string) error {
	fs, err := cli.Flags("scripts col order", args, nil)
	if err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return errors.New("uso: mctl scripts col order ID [ID]  (todas las colecciones, también favoritos)")
	}
	if _, err := client(c).ReorderCollections(context.Background(), &v1.ReorderCollectionsRequest{Ids: fs.Args()}); err != nil {
		return err
	}
	fmt.Fprintln(c.Out, "orden guardado")
	return nil
}

// scripts col export --out RUTA [--overwrite] ID...
func colExport(c *cli.Env, args []string) error {
	var out string
	var ow bool
	fs, err := cli.Flags("scripts col export", args, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "out", "", "archivo de salida")
		fs.BoolVar(&ow, "overwrite", false, "reemplaza el archivo si existe")
	})
	if err != nil {
		return err
	}
	if out == "" || fs.NArg() < 1 {
		return errors.New("uso: mctl scripts col export --out RUTA [--overwrite] ID [ID]")
	}
	if out, err = filepath.Abs(out); err != nil {
		return err
	}
	r, err := client(c).ExportCollections(context.Background(), &v1.ExportCollectionsRequest{Ids: fs.Args(), Path: out, Overwrite: ow})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "exportadas %d colecciones y %d scripts a %s\n", r.Collections, r.Scripts, out)
	return nil
}

// parseDecs valida --decision y --all; las claves son IDs del archivo (de colección o de script).
func parseDecs(decs cli.List, all string) (map[string]string, error) {
	if all != "" && !acciones[all] {
		return nil, fmt.Errorf("--all=%q: use renombrar, reemplazar u omitir", all)
	}
	dec := map[string]string{}
	for _, d := range decs {
		id, act, ok := strings.Cut(d, "=")
		if !ok || id == "" || !acciones[act] {
			return nil, fmt.Errorf("--decision %q: use ID=renombrar|reemplazar|omitir", d)
		}
		dec[id] = act
	}
	return dec, nil
}

func conflicto(state string) bool { return state == "conflicto_id" || state == "conflicto_nombre" }

// scripts col import RUTA [--decision ID=acción]... [--all=acción] [--preview]
// Las decisiones valen para colecciones y para scripts del archivo: se enrutan por el ID.
func colImport(c *cli.Env, args []string) error {
	var decs cli.List
	var all string
	var onlyPreview bool
	fs, err := cli.Flags("scripts col import", args, func(fs *flag.FlagSet) {
		fs.Var(&decs, "decision", "ID=acción para un conflicto de colección o de script (repetible)")
		fs.StringVar(&all, "all", "", "acción para los conflictos sin --decision")
		fs.BoolVar(&onlyPreview, "preview", false, "solo la vista previa")
	})
	if err != nil {
		return err
	}
	const uso = "uso: mctl scripts col import RUTA [--decision ID=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]"
	if fs.NArg() != 1 {
		return errors.New(uso)
	}
	dec, err := parseDecs(decs, all)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	cl := client(c)
	p, err := cl.PreviewImportCollections(context.Background(), &v1.PreviewImportCollectionsRequest{Path: path})
	if err != nil {
		return err
	}
	var cdec, sdec []*v1.ImportDecision
	var missing []string
	known := map[string]bool{}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIPO\tID\tNOMBRE\tESTADO\tCHOCA CON")
	decide := func(id, state string, into *[]*v1.ImportDecision) {
		known[id] = true
		a, ok := dec[id]
		if !ok && conflicto(state) {
			if a = all; a == "" {
				missing = append(missing, id)
				return
			}
			ok = true
		}
		if ok {
			*into = append(*into, &v1.ImportDecision{ScriptId: id, Action: a})
		}
	}
	for _, it := range p.Collections {
		fmt.Fprintf(tw, "colección\t%s\t%s\t%s\t%s\n", it.Collection.Id, it.Collection.Name, it.State, it.ConflictsWith)
		decide(it.Collection.Id, it.State, &cdec)
	}
	for _, it := range p.Scripts {
		fmt.Fprintf(tw, "script\t%s\t%s\t%s\t%s\n", it.Script.Id, it.Script.Name, it.State, it.ConflictsWith)
		decide(it.Script.Id, it.State, &sdec)
	}
	tw.Flush()
	for _, w := range p.Warnings {
		fmt.Fprintf(c.Out, "aviso: %s\n", w)
	}
	for id := range dec {
		if !known[id] {
			return fmt.Errorf("--decision %s: no es una colección ni un script del archivo", id)
		}
	}
	if onlyPreview {
		return nil
	}
	if len(missing) > 0 {
		return fmt.Errorf("no se importó nada: falta decidir %d conflicto(s); use --decision ID=renombrar|reemplazar|omitir o --all=ACCIÓN: %s", len(missing), strings.Join(missing, ", "))
	}
	r, err := cl.ApplyImportCollections(context.Background(), &v1.ApplyImportCollectionsRequest{Token: p.Token, ScriptDecisions: sdec, CollectionDecisions: cdec})
	if err != nil {
		return err
	}
	for _, w := range r.Warnings {
		fmt.Fprintf(c.Out, "aviso: %s\n", w)
	}
	fmt.Fprintf(c.Out, "importadas: %d nuevas, %d reemplazadas, %d renombradas, %d fusionadas, %d omitidas; scripts: %d nuevos, %d reemplazados, %d renombrados, %d omitidos\n",
		r.CollectionsCreated, r.CollectionsReplaced, r.CollectionsRenamed, r.CollectionsMerged, r.CollectionsSkipped, r.ScriptsCreated, r.ScriptsReplaced, r.ScriptsRenamed, r.ScriptsSkipped)
	return nil
}

// scripts pin [ID [--off]] | scripts pin --order ID...
// Sin argumentos lista los fijados en su orden (máximo 5).
func pin(c *cli.Env, args []string) error {
	var off, order bool
	fs, err := cli.Flags("scripts pin", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&off, "off", false, "desfija")
		fs.BoolVar(&order, "order", false, "deja los fijados en el orden de los ID dados (todos)")
	})
	if err != nil {
		return err
	}
	const uso = "uso: mctl scripts pin [ID [--off]]  |  mctl scripts pin --order ID [ID]"
	cl := client(c)
	switch {
	case order && !off && fs.NArg() >= 1:
		if _, err := cl.ReorderPinned(context.Background(), &v1.ReorderPinnedRequest{Ids: fs.Args()}); err != nil {
			return err
		}
		fmt.Fprintln(c.Out, "orden de fijados guardado")
	case !order && fs.NArg() == 1:
		if _, err := cl.SetPinned(context.Background(), &v1.SetPinnedRequest{Id: fs.Arg(0), Pinned: !off}); err != nil {
			return err
		}
		fmt.Fprintf(c.Out, "%s %s\n", map[bool]string{true: "desfijado:", false: "fijado:"}[off], fs.Arg(0))
	case !order && !off && fs.NArg() == 0:
		res, err := cl.ListPinned(context.Background(), &v1.ListPinnedRequest{})
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "N\tID\tNOMBRE\tMODO")
		for i, s := range res.Scripts {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", i+1, s.Id, s.Name, ro(s.ReadOnly))
		}
		return tw.Flush()
	default:
		return errors.New(uso)
	}
	return nil
}

// scripts template [--kind scripts|colecciones] [--fields]
func template(c *cli.Env, args []string) error {
	kind, fields := "scripts", false
	fs, err := cli.Flags("scripts template", args, func(fs *flag.FlagSet) {
		fs.StringVar(&kind, "kind", "scripts", "scripts o colecciones")
		fs.BoolVar(&fields, "fields", false, "lista de campos en vez del ejemplo")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("uso: mctl scripts template [--kind scripts|colecciones] [--fields]")
	}
	cl := client(c)
	if !fields {
		r, err := cl.ImportTemplate(context.Background(), &v1.ImportTemplateRequest{Kind: kind})
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, r.Json)
		return nil
	}
	r, err := cl.ImportFormat(context.Background(), &v1.ImportFormatRequest{Kind: kind})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "CAMPO\tTIPO\tOBLIGATORIO\tEJEMPLO\tDESCRIPCIÓN")
	for _, f := range r.Fields {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", f.Name, f.Type, map[bool]string{true: "sí", false: "no"}[f.Required], f.Example, f.Description)
	}
	return tw.Flush()
}
