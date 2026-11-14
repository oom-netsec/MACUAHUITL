package snippet

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// list imprime el catálogo de plantillas por tecnología, con los campos de cada una.
func list(c *cli.Env, args []string) error {
	var platform string
	var asJSON bool
	fs, err := cli.Flags("snippet list", args, func(fs *flag.FlagSet) {
		fs.StringVar(&platform, "platform", "", "ios o ios-xe; vacío = todas")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil || fs.NArg() != 0 {
		return errors.New("uso: mctl snippet list [--platform P] [--json]")
	}
	res, err := v1.NewAssistServiceClient(c.Conn).ListSnippetTemplates(context.Background(), &v1.ListSnippetTemplatesRequest{Platform: platform})
	if err != nil {
		return err
	}
	if asJSON {
		b, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(res)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, string(b))
		return nil
	}
	tech := ""
	for _, t := range res.Templates {
		if t.Tech != tech {
			tech = t.Tech
			fmt.Fprintf(c.Out, "\n%s\n", tech)
		}
		fmt.Fprintf(c.Out, "  %s: %s [%s]\n", t.Id, t.Name, strings.Join(t.Platforms, ", "))
		for _, f := range t.Fields {
			fmt.Fprintf(c.Out, "      --set %s=  %s\n", f.Name, describeField(f))
		}
	}
	return nil
}

// describeField resume el tipo, los límites y la ayuda de un campo en una línea.
func describeField(f *v1.SnippetField) string {
	parts := []string{f.Type}
	if len(f.Choices) > 0 {
		parts = append(parts, strings.Join(f.Choices, "|"))
	}
	if f.Min != 0 || f.Max != 0 {
		parts = append(parts, fmt.Sprintf("%g-%g", f.Min, f.Max))
	}
	if f.Required {
		parts = append(parts, cli.T("mctl.snippet.required"))
	}
	s := strings.Join(parts, " ") + "  " + f.Label
	if f.Help != "" {
		s += ". " + f.Help
	}
	return s
}

// parseSets lee los --set campo=valor (el valor puede llevar «=»; un campo no se repite).
func parseSets(sets cli.List) (map[string]string, error) {
	out := map[string]string{}
	for _, s := range sets {
		k, v, ok := strings.Cut(s, "=")
		if !ok || k == "" {
			return nil, cli.Err("mctl.snippet.bad_set", "value", k)
		}
		if _, dup := out[k]; dup {
			return nil, cli.Err("mctl.snippet.dup_set", "name", k)
		}
		out[k] = v
	}
	return out, nil
}

// fillSecrets pide, sin eco, cada secreto obligatorio que no llegó en --set. Nunca lo imprime.
func fillSecrets(c *cli.Env, t *v1.SnippetTemplate, vals map[string]string) error {
	for _, f := range t.Fields {
		if f.Type != "secret" || !f.Required || vals[f.Name] != "" {
			continue
		}
		b, err := c.Secret(f.Label + ": ")
		if err != nil {
			return err
		}
		vals[f.Name] = string(b)
		cli.Wipe(b)
		if vals[f.Name] == "" {
			return cli.Err("mctl.snippet.empty", "label", f.Label)
		}
	}
	return nil
}

// run planea (y con --asistido ejecuta) una plantilla del catálogo con los valores de --set.
func run(c *cli.Env, args []string) error {
	var g common
	var sets cli.List
	fs, err := cli.Flags("snippet run", args, func(fs *flag.FlagSet) {
		g.flags(fs)
		fs.Var(&sets, "set", "campo=valor (repetible)")
	})
	if err != nil || fs.NArg() != 2 || g.credID == "" {
		return errors.New("uso: mctl snippet run EQUIPO[:PUERTO] ID --cred ID [--set campo=valor]... [--asistido]  (mctl snippet list muestra los campos)")
	}
	vals, err := parseSets(sets)
	if err != nil {
		return err
	}
	res, err := v1.NewAssistServiceClient(c.Conn).ListSnippetTemplates(context.Background(), &v1.ListSnippetTemplatesRequest{})
	if err != nil {
		return err
	}
	var tpl *v1.SnippetTemplate
	for _, t := range res.Templates {
		if t.Id == fs.Arg(1) {
			tpl = t
		}
	}
	if tpl == nil {
		return cli.Err("mctl.snippet.no_template", "id", fs.Arg(1))
	}
	if err := fillSecrets(c, tpl, vals); err != nil {
		return err
	}
	return plan(c, fs.Arg(0), &g, func(r *v1.PlanSnippetRequest) {
		r.Snippet = &v1.PlanSnippetRequest_Template{Template: &v1.TemplateSnippet{Id: tpl.Id, Values: vals}}
	})
}
