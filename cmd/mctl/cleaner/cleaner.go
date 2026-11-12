package cleaner

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func clean(c *cli.Env, args []string) error {
	var out string
	var sort, asJSON bool
	fs, err := cli.Flags("config clean", args, func(fs *flag.FlagSet) {
		fs.StringVar(&out, "o", "", "archivo de salida (sin -o solo se muestra el informe)")
		fs.BoolVar(&sort, "sort", false, "ordena interfaces, VLAN, rutas estáticas y usuarios contiguos")
		fs.BoolVar(&asJSON, "json", false, "informe en JSON")
	})
	if err != nil || fs.NArg() != 1 {
		return errors.New("uso: mctl config clean ARCHIVO [-o SALIDA] [--sort] [--json]")
	}
	in := fs.Arg(0)
	text, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	if out != "" {
		// Stat sigue enlaces simbólicos y SameFile reconoce los duros: ambos apuntan al original.
		si, _ := os.Stat(in)
		if so, err := os.Stat(out); err == nil && os.SameFile(si, so) {
			return errors.New("la salida no puede ser el archivo de entrada: la limpieza no sobrescribe el original")
		}
	}
	r, err := v1.NewCleanerServiceClient(c.Conn).Clean(context.Background(), &v1.CleanRequest{Text: string(text), Sort: sort})
	if err != nil {
		return err
	}
	if out != "" {
		if err := writeNew(out, r.Output); err != nil {
			return err
		}
		if !asJSON {
			fmt.Fprintf(c.Out, "escrito %s\n", out)
		}
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

// writeNew crea el archivo solo si no existe (O_EXCL tampoco sigue enlaces simbólicos): nunca pisa ni cambia permisos.
func writeNew(path, text string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("no se escribe la salida (¿ya existe?): %w", err)
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

const help = `  config clean ARCHIVO [-o SALIDA] [--sort] [--json]
        (quita vacías y ! repetidos, recorta espacios, marca huérfanas; sin -o solo muestra el informe)`

// Area registra config clean.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "config clean", Run: clean}}}
}
