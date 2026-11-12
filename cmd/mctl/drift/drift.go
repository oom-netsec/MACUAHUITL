package drift

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// jobArg: una carpeta se resuelve en el cliente; lo demás es el ID de un trabajo.
func jobArg(s string) string {
	if fi, err := os.Stat(s); err == nil && fi.IsDir() {
		if abs, err := filepath.Abs(s); err == nil {
			return abs
		}
	}
	return s
}

func run(c *cli.Env, args []string) error {
	var round int
	var device string
	var asJSON bool
	fs, err := cli.Flags("drift", args, func(fs *flag.FlagSet) {
		fs.IntVar(&round, "round", 0, "ronda a comparar con la anterior (0 = la última)")
		fs.StringVar(&device, "device", "", "equipo (parte del nombre o la IP)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 || round < 0 {
		return fmt.Errorf("uso: mctl drift TRABAJO|CARPETA [--round N] [--device EQUIPO] [--json]")
	}
	r, err := v1.NewDriftServiceClient(c.Conn).Drift(context.Background(), &v1.DriftRequest{Job: jobArg(fs.Arg(0)), Round: uint32(round), Device: device})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

const help = `  drift TRABAJO|CARPETA [--round N] [--device EQUIPO] [--json]
        (running-config de la ronda N contra la N-1 por equipo, sin líneas volátiles; solo lee)`

// Area registra drift.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{{Name: "drift", Run: run}}}
}
