// Package scripts es el área de mctl de la bóveda de scripts: los del usuario más la biblioteca predefinida,
// favoritos y export/import a un archivo. Nada de esto toca un equipo (ADR 0007).
package scripts

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const maxCommandsFile = 1 << 20 // 200 líneas de 512 caben de sobra

func client(c *cli.Env) v1.ScriptsServiceClient { return v1.NewScriptsServiceClient(c.Conn) }

func printJSON(c *cli.Env, m proto.Message) error {
	b, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(m)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, string(b))
	return nil
}

// readCommands lee los comandos de un archivo regular o de stdin («-» o sin --file): una línea por comando;
// quita el retorno de carro y salta las líneas en blanco.
func readCommands(c *cli.Env, file string) ([]string, error) {
	var r io.Reader = c.In
	if file != "" && file != "-" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s no es un archivo regular", file)
		}
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxCommandsFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxCommandsFile {
		return nil, errors.New("los comandos pasan de 1 MiB")
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		if ln = strings.TrimSuffix(ln, "\r"); strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out, nil
}

func ts(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04") }

func star(fav bool) string {
	if fav {
		return "*"
	}
	return ""
}

func ro(b bool) string {
	if b {
		return "lectura"
	}
	return "configura"
}

// scripts list [TEXTO] [--tech T] [--platform P] [--tag X] [--fav] [--json]
func list(c *cli.Env, args []string) error {
	var r v1.ListScriptsRequest
	var asJSON bool
	fs, err := cli.Flags("scripts list", args, func(fs *flag.FlagSet) {
		fs.StringVar(&r.Tech, "tech", "", "tecnología")
		fs.StringVar(&r.Platform, "platform", "", "plataforma")
		fs.StringVar(&r.Tag, "tag", "", "etiqueta")
		fs.BoolVar(&r.OnlyFavorites, "fav", false, "solo favoritos")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("uso: mctl scripts list [TEXTO] [--tech T] [--platform P] [--tag X] [--fav] [--json]")
	}
	r.Text = fs.Arg(0)
	res, err := client(c).ListScripts(context.Background(), &r)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(c, res)
	}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tFAV\tNOMBRE\tTECNOLOGÍA\tPLATAFORMA\tMODO\tORIGEN")
	for _, s := range res.Scripts {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.Id, star(s.Favorite), s.Name, s.Tech, s.Platform, ro(s.ReadOnly), s.Origin)
	}
	return tw.Flush()
}

// scripts show ID [--json]
func show(c *cli.Env, args []string) error {
	var asJSON bool
	fs, err := cli.Flags("scripts show", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "salida JSON") })
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl scripts show ID [--json]")
	}
	res, err := client(c).GetScript(context.Background(), &v1.GetScriptRequest{Id: fs.Arg(0)})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(c, res)
	}
	s := res.Script
	fmt.Fprintf(c.Out, "%s%s\n  id: %s · %s · %s · %s · %s%s\n", s.Name, map[bool]string{true: " *", false: ""}[s.Favorite], s.Id, s.Origin, s.Tech, s.Platform, ro(s.ReadOnly),
		map[bool]string{true: " · fijado", false: ""}[s.Pinned])
	if len(s.Collections) > 0 {
		fmt.Fprintf(c.Out, "  colecciones: %s\n", strings.Join(s.Collections, ", "))
	}
	if s.Description != "" {
		fmt.Fprintf(c.Out, "  %s\n", s.Description)
	}
	if len(s.Tags) > 0 {
		fmt.Fprintf(c.Out, "  etiquetas: %s\n", strings.Join(s.Tags, ", "))
	}
	fmt.Fprintf(c.Out, "  creado: %s · editado: %s\n\n", ts(s.CreatedMs), ts(s.UpdatedMs))
	for _, ln := range s.Commands {
		fmt.Fprintln(c.Out, ln)
	}
	return nil
}

type fields struct {
	name, tech, platform, desc, file string
	tags                             cli.List
}

func (f *fields) flags(fs *flag.FlagSet) {
	fs.StringVar(&f.name, "name", "", "nombre")
	fs.StringVar(&f.tech, "tech", "", "tecnología")
	fs.StringVar(&f.platform, "platform", "", "plataforma")
	fs.StringVar(&f.desc, "desc", "", "descripción")
	fs.StringVar(&f.file, "file", "", "archivo con los comandos, uno por línea («-» o sin --file: stdin)")
	fs.Var(&f.tags, "tag", "etiqueta (repetible)")
}

func saved(c *cli.Env, verb string, s *v1.Script) {
	fmt.Fprintf(c.Out, "%s %s (%s)\n", verb, s.Id, s.Name)
}

// scripts add NOMBRE --tech T --platform P [--desc D] [--tag X]... [--file F|-]
func add(c *cli.Env, args []string) error {
	var f fields
	fs, err := cli.Flags("scripts add", args, func(fs *flag.FlagSet) { f.flags(fs) })
	if err != nil {
		return err
	}
	if fs.NArg() != 1 || f.name != "" {
		return errors.New("uso: mctl scripts add NOMBRE --tech T --platform P [--desc D] [--tag X]... [--file F|-]")
	}
	cmds, err := readCommands(c, f.file)
	if err != nil {
		return err
	}
	r, err := client(c).SaveScript(context.Background(), &v1.SaveScriptRequest{Script: &v1.Script{Name: fs.Arg(0), Tech: f.tech, Platform: f.platform,
		Description: f.desc, Commands: cmds, Tags: f.tags}})
	if err != nil {
		return err
	}
	saved(c, "creado", r.Script)
	return nil
}

// scripts edit ID [--name N] [--tech T] [--platform P] [--desc D] [--tag X]... [--file F|-]
// Solo cambia lo que se pasa; --tag reemplaza todas las etiquetas y --file todos los comandos.
func edit(c *cli.Env, args []string) error {
	var f fields
	fs, err := cli.Flags("scripts edit", args, func(fs *flag.FlagSet) { f.flags(fs) })
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl scripts edit ID [--name N] [--tech T] [--platform P] [--desc D] [--tag X]... [--file F|-]")
	}
	set := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	cl := client(c)
	cur, err := cl.GetScript(context.Background(), &v1.GetScriptRequest{Id: fs.Arg(0)})
	if err != nil {
		return err
	}
	s := cur.Script
	if set["name"] {
		s.Name = f.name
	}
	if set["tech"] {
		s.Tech = f.tech
	}
	if set["platform"] {
		s.Platform = f.platform
	}
	if set["desc"] {
		s.Description = f.desc
	}
	if set["tag"] {
		s.Tags = f.tags
	}
	if set["file"] {
		if s.Commands, err = readCommands(c, f.file); err != nil {
			return err
		}
	}
	r, err := cl.SaveScript(context.Background(), &v1.SaveScriptRequest{Script: s})
	if err != nil {
		return err
	}
	saved(c, "guardado", r.Script)
	return nil
}

// scripts rm ID
func rm(c *cli.Env, args []string) error {
	id, err := cli.OneArg("scripts rm", args)
	if err != nil {
		return err
	}
	if _, err := client(c).DeleteScript(context.Background(), &v1.DeleteScriptRequest{Id: id}); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "borrado %s\n", id)
	return nil
}

// scripts fav ID [--off]
func fav(c *cli.Env, args []string) error {
	var off bool
	fs, err := cli.Flags("scripts fav", args, func(fs *flag.FlagSet) { fs.BoolVar(&off, "off", false, "quita el favorito") })
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl scripts fav ID [--off]")
	}
	if _, err := client(c).SetFavorite(context.Background(), &v1.SetFavoriteRequest{Id: fs.Arg(0), Favorite: !off}); err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "%s %s\n", map[bool]string{true: "favorito quitado:", false: "favorito:"}[off], fs.Arg(0))
	return nil
}

// scripts dup ID
func dup(c *cli.Env, args []string) error {
	id, err := cli.OneArg("scripts dup", args)
	if err != nil {
		return err
	}
	r, err := client(c).DuplicateScript(context.Background(), &v1.DuplicateScriptRequest{Id: id})
	if err != nil {
		return err
	}
	saved(c, "creado", r.Script)
	return nil
}

// scripts export --out RUTA [--overwrite] ID...
func export(c *cli.Env, args []string) error {
	var out string
	var ow bool
	fs, err := cli.Flags("scripts export", args, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "out", "", "archivo de salida")
		fs.BoolVar(&ow, "overwrite", false, "reemplaza el archivo si existe")
	})
	if err != nil {
		return err
	}
	if out == "" || fs.NArg() < 1 {
		return errors.New("uso: mctl scripts export --out RUTA [--overwrite] ID [ID]")
	}
	if out, err = filepath.Abs(out); err != nil {
		return err
	}
	r, err := client(c).ExportScripts(context.Background(), &v1.ExportScriptsRequest{Ids: fs.Args(), Path: out, Overwrite: ow})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "exportados %d scripts a %s\n", r.Count, out)
	return nil
}

var acciones = map[string]bool{"renombrar": true, "reemplazar": true, "omitir": true}

// scripts import RUTA [--decision ID=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]
func importCmd(c *cli.Env, args []string) error {
	var decs cli.List
	var all string
	var onlyPreview bool
	fs, err := cli.Flags("scripts import", args, func(fs *flag.FlagSet) {
		fs.Var(&decs, "decision", "ID=acción para un conflicto (repetible)")
		fs.StringVar(&all, "all", "", "acción para los conflictos sin --decision")
		fs.BoolVar(&onlyPreview, "preview", false, "solo la vista previa")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl scripts import RUTA [--decision ID=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]")
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
	p, err := cl.PreviewImport(context.Background(), &v1.PreviewImportRequest{Path: path})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNOMBRE\tESTADO\tCHOCA CON")
	var req []*v1.ImportDecision
	var missing []string
	for _, it := range p.Items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", it.Script.Id, it.Script.Name, it.State, it.ConflictsWith)
		if it.State != "conflicto_id" && it.State != "conflicto_nombre" {
			if a, ok := dec[it.Script.Id]; ok {
				req = append(req, &v1.ImportDecision{ScriptId: it.Script.Id, Action: a})
			}
			continue
		}
		a, ok := dec[it.Script.Id]
		if !ok {
			if a = all; a == "" {
				missing = append(missing, it.Script.Id)
				continue
			}
		}
		req = append(req, &v1.ImportDecision{ScriptId: it.Script.Id, Action: a})
	}
	tw.Flush()
	for _, w := range p.Warnings {
		fmt.Fprintf(c.Out, "aviso: %s\n", w)
	}
	if onlyPreview {
		return nil
	}
	if len(missing) > 0 {
		return fmt.Errorf("no se importó nada: falta decidir %d conflicto(s); use --decision ID=renombrar|reemplazar|omitir o --all=ACCIÓN: %s", len(missing), strings.Join(missing, ", "))
	}
	r, err := cl.ApplyImport(context.Background(), &v1.ApplyImportRequest{Token: p.Token, Decisions: req})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "importados: %d nuevos, %d reemplazados, %d renombrados, %d omitidos\n", r.Created, r.Replaced, r.Renamed, r.Skipped)
	return nil
}

const help = `  scripts list [TEXTO] [--tech T] [--platform P] [--tag X] [--fav] [--json]  |  scripts show ID [--json]
        (bóveda de scripts: los tuyos más la biblioteca predefinida, ordenados por nombre; MODO lectura = Patrol puede correrlo. Los IDs «lib-*» son de la biblioteca y no se editan)
  scripts add NOMBRE --tech T --platform P [--desc D] [--tag X]... [--file F|-]
  scripts edit ID [--name N] [--tech T] [--platform P] [--desc D] [--tag X]... [--file F|-]
        (los comandos van uno por línea, de un archivo o de stdin; edit solo cambia lo que se pasa y --tag o --file reemplazan la lista entera.
         tech: l2, l3, gestion, seguridad, qos, etherchannel, wireless, diagnostico, otro; platform: ios, ios-xe, nx-os, asa, cualquiera)
  scripts rm ID  |  scripts fav ID [--off]  |  scripts dup ID
        (borra uno tuyo, marca o quita un favorito (también en la biblioteca), o copia cualquiera como script tuyo)
  scripts export --out RUTA [--overwrite] ID...
        (archivo JSON 0600 con la suma SHA-256 de los scripts (integridad, no autenticidad); no sobrescribe sin --overwrite; los favoritos no viajan)
  scripts import RUTA [--decision ID=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]
        (muestra el estado de cada script: nuevo, igual, conflicto_id o conflicto_nombre; los nuevos entran solos y cada conflicto necesita una decisión, si no, no se importa nada)
  scripts col list [--json]  |  scripts col show ID [--json]  |  scripts col add NOMBRE [--desc D]  |  scripts col edit ID [--name N] [--desc D]  |  scripts col rm ID
        (colecciones: listas ordenadas de IDs de script, también de la biblioteca, que no se copian; un script puede estar en varias y borrarlo lo quita de todas.
         «favoritos» es la colección por defecto: no se borra ni se renombra, y scripts fav la usa)
  scripts col set ID [SCRIPT_ID...] [--add ID]... [--rm ID]... [--clear]  |  scripts col order ID...
        (set deja exactamente los SCRIPT_ID dados y en ese orden; sin ellos parte de lo que hay y aplica --rm y --add; order reordena todas las colecciones, también favoritos)
  scripts col export --out RUTA [--overwrite] ID...
  scripts col import RUTA [--decision ID=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]
        (el archivo lleva las colecciones y los scripts de usuario que referencian; los de biblioteca van por ID y los que esta biblioteca no trae se avisan y se omiten.
         Estados: nueva, igual, fusionar (favoritos: se le agregan los que falten, nunca se reemplaza), conflicto_id y conflicto_nombre; las decisiones de colecciones y de scripts del archivo van con --decision por ID)
  scripts template [--kind scripts|colecciones] [--fields]
        (imprime un archivo de ejemplo que el import acepta tal cual, o con --fields la lista de campos con su tipo, si son obligatorios, un ejemplo y su descripción. Ambos salen de las mismas reglas que validan el import. El sha256 es opcional: sin él se valida campo por campo y el import avisa)
  scripts pin [ID [--off]]  |  scripts pin --order ID...
        (barra corta de la terminal: máximo 5 scripts fijados, aparte de las colecciones; sin argumentos los lista en su orden)`

// Area registra los comandos de la bóveda de scripts.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "scripts list", Run: list}, {Name: "scripts show", Run: show},
		{Name: "scripts add", Run: add}, {Name: "scripts edit", Run: edit},
		{Name: "scripts rm", Run: rm}, {Name: "scripts fav", Run: fav}, {Name: "scripts dup", Run: dup},
		{Name: "scripts export", Run: export}, {Name: "scripts import", Run: importCmd},
		{Name: "scripts col", Run: col}, {Name: "scripts pin", Run: pin}, {Name: "scripts template", Run: template},
	}}
}
