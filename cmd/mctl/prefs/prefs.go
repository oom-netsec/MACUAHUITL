// Package prefs es el área de mctl para las preferencias del núcleo (fase 29e): la carpeta base de salidas y los
// defaults de archivo que usan syslog, traps y flujos cuando no se piden opciones.
package prefs

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

const help = `  prefs show [--json]  |  prefs set [--outputs DIR] [--rotate-mb N] [--rotate-min N] [--max-files N] [--format F]
        (set cambia solo lo que se pide; 0 o "" devuelve ese valor al de fábrica. La carpeta debe ser absoluta, existir, ser tuya, escribible y de modo 0700;
         aplica a lo que empiece después y los datos de la anterior no se mueven. rotate-mb 1-1024, rotate-min 1-10080, max-files 1-1000, format texto|crudo|jsonl)`

func orDefault(n int32) string {
	if n == 0 {
		return cli.T("mctl.prefs.default")
	}
	return fmt.Sprint(n)
}

func show(c *cli.Env, st *v1.CorePrefsState, asJSON bool) error {
	if asJSON {
		b, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(st)
		if err != nil {
			return err
		}
		var pretty json.RawMessage = b
		out, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Fprintln(c.Out, string(out))
		return nil
	}
	suffix := ""
	if st.Prefs.GetOutputsDir() == "" {
		suffix = " (" + cli.T("mctl.prefs.default") + ")"
	}
	in := st.Prefs.GetIngestDefaults()
	format := in.GetFormat()
	if format == "" {
		format = cli.T("mctl.prefs.default")
	}
	fmt.Fprintln(c.Out, cli.T("mctl.prefs.show", "dir", st.OutputsDirEffective, "suffix", suffix, "mb", orDefault(in.GetRotateMb()), "min", orDefault(in.GetRotateMinutes()), "max", orDefault(in.GetMaxFiles()), "format", format))
	if st.Note != "" {
		fmt.Fprintln(c.Out, st.Note)
	}
	return nil
}

func get(c *cli.Env, args []string) error {
	var asJSON bool
	fs, err := cli.Flags("prefs show", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "salida en JSON") })
	if err != nil || fs.NArg() != 0 {
		return errors.New("uso: mctl prefs show [--json]")
	}
	r, err := v1.NewPrefsServiceClient(c.Conn).GetCorePrefs(context.Background(), &v1.GetCorePrefsRequest{})
	if err != nil {
		return err
	}
	return show(c, r.State, asJSON)
}

func set(c *cli.Env, args []string) error {
	var outputs, format string
	var mb, mins, maxFiles int
	fs, err := cli.Flags("prefs set", args, func(fs *flag.FlagSet) {
		fs.StringVar(&outputs, "outputs", "", "carpeta base de salidas (vacía = la de fábrica)")
		fs.IntVar(&mb, "rotate-mb", 0, "rotar cada N MB (0 = de fábrica; 1-1024)")
		fs.IntVar(&mins, "rotate-min", 0, "rotar cada N minutos (0 = de fábrica; 1-10080)")
		fs.IntVar(&maxFiles, "max-files", 0, "archivos que se conservan (0 = de fábrica; 1-1000)")
		fs.StringVar(&format, "format", "", "texto, crudo o jsonl (vacío = de fábrica)")
	})
	given := map[string]bool{}
	if err == nil {
		fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	}
	if err != nil || fs.NArg() != 0 || len(given) == 0 {
		return errors.New("uso: mctl prefs set [--outputs DIR] [--rotate-mb N] [--rotate-min N] [--max-files N] [--format F]")
	}
	cl := v1.NewPrefsServiceClient(c.Conn)
	cur, err := cl.GetCorePrefs(context.Background(), &v1.GetCorePrefsRequest{})
	if err != nil {
		return err
	}
	p := cur.State.Prefs
	if p.IngestDefaults == nil {
		p.IngestDefaults = &v1.IngestDefaults{}
	}
	in := p.IngestDefaults
	for _, n := range []struct {
		name string
		v    int
		dst  *int32
	}{{"rotate-mb", mb, &in.RotateMb}, {"rotate-min", mins, &in.RotateMinutes}, {"max-files", maxFiles, &in.MaxFiles}} {
		if !given[n.name] {
			continue
		}
		if *n.dst, err = cli.Int32(n.name, n.v); err != nil {
			return err
		}
	}
	if given["outputs"] {
		p.OutputsDir = outputs
	}
	if given["format"] {
		in.Format = format
	}
	r, err := cl.SetCorePrefs(context.Background(), &v1.SetCorePrefsRequest{Prefs: p})
	if err != nil {
		return err
	}
	return show(c, r.State, false)
}

// Area registra prefs show y prefs set.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "prefs show", Run: get}, {Name: "prefs set", Run: set}}}
}
