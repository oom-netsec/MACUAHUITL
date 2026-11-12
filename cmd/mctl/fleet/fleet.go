package fleet

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// fleetCmd arma un comando de la flota: n argumentos posicionales, --dir y --json.
func fleetCmd(name string, nargs int, usage string, extra func(fs *flag.FlagSet), run func(c *cli.Env, args []string, dir string, asJSON bool) error) func(*cli.Env, []string) error {
	return func(c *cli.Env, args []string) error {
		var dir string
		var asJSON bool
		fs, err := cli.Flags(name, args, func(fs *flag.FlagSet) {
			fs.StringVar(&dir, "dir", "", "carpeta de outputs (por defecto la de la app)")
			fs.BoolVar(&asJSON, "json", false, "salida JSON")
			if extra != nil {
				extra(fs)
			}
		})
		if err != nil || fs.NArg() != nargs {
			return fmt.Errorf("uso: mctl %s", usage)
		}
		if dir != "" {
			if dir, err = filepath.Abs(dir); err != nil {
				return err
			}
		}
		return run(c, fs.Args(), dir, asJSON)
	}
}

// Area registra find, trace, path, health y fleet.
func Area() cli.Area {
	var svg, need string
	var csv, md bool
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "find", Run: fleetCmd("find", 1, "find IP|MAC|NOMBRE [--dir D] [--json]", nil, func(c *cli.Env, a []string, dir string, j bool) error {
			r, err := v1.NewFleetServiceClient(c.Conn).Find(context.Background(), &v1.FindRequest{Dir: dir, Query: a[0]})
			if err == nil {
				c.PrintReport(r.Report, j)
			}
			return err
		})},
		{Name: "trace", Run: fleetCmd("trace", 1, "trace MAC|IP [--dir D] [--json]", nil, func(c *cli.Env, a []string, dir string, j bool) error {
			r, err := v1.NewFleetServiceClient(c.Conn).Trace(context.Background(), &v1.TraceRequest{Dir: dir, Query: a[0]})
			if err == nil {
				c.PrintReport(r.Report, j)
			}
			return err
		})},
		{Name: "path", Run: fleetCmd("path", 2, "path ORIGEN DESTINO [--svg ARCHIVO] [--dir D] [--json]", func(fs *flag.FlagSet) {
			fs.StringVar(&svg, "svg", "", "guarda el grafo del camino como SVG")
		}, func(c *cli.Env, a []string, dir string, j bool) error {
			r, err := v1.NewFleetServiceClient(c.Conn).Path(context.Background(), &v1.PathRequest{Dir: dir, Query: a[0], Dst: a[1]})
			if err != nil {
				return err
			}
			if svg != "" {
				if err := os.WriteFile(svg, []byte(r.Svg), 0o600); err != nil {
					return err
				}
			}
			c.PrintReport(r.Report, j)
			return nil
		})},
		{Name: "health interfaces", Run: fleetCmd("health interfaces", 0, "health interfaces [--dir D] [--json]", nil, func(c *cli.Env, _ []string, dir string, j bool) error {
			r, err := v1.NewFleetServiceClient(c.Conn).Health(context.Background(), &v1.HealthRequest{Dir: dir})
			if err == nil {
				c.PrintReport(r.Report, j)
			}
			return err
		})},
		{Name: "fleet summary", Run: fleetCmd("fleet summary", 0, "fleet summary [--dir D] [--json]", nil, func(c *cli.Env, _ []string, dir string, j bool) error {
			r, err := v1.NewFleetServiceClient(c.Conn).Summary(context.Background(), &v1.SummaryRequest{Dir: dir})
			if err == nil {
				c.PrintReport(r.Report, j)
			}
			return err
		})},
		{Name: "fleet flash", Run: fleetCmd("fleet flash", 0, "fleet flash [--need TAMAÑO] [--dir D] [--json]", func(fs *flag.FlagSet) {
			fs.StringVar(&need, "need", "", "tamaño que debe caber (800M, 1.2G)")
		}, func(c *cli.Env, _ []string, dir string, j bool) error {
			r, err := v1.NewFleetServiceClient(c.Conn).Capacity(context.Background(), &v1.CapacityRequest{Dir: dir, Need: need})
			if err == nil {
				c.PrintReport(r.Report, j)
			}
			return err
		})},
		{Name: "fleet inventory", Run: fleetCmd("fleet inventory", 0, "fleet inventory [--csv|--md] [--dir D] [--json]", func(fs *flag.FlagSet) {
			fs.BoolVar(&csv, "csv", false, "salida CSV")
			fs.BoolVar(&md, "md", false, "salida Markdown")
		}, func(c *cli.Env, _ []string, dir string, j bool) error {
			r, err := v1.NewFleetServiceClient(c.Conn).Inventory(context.Background(), &v1.InventoryRequest{Dir: dir})
			if err != nil {
				return err
			}
			switch {
			case csv:
				fmt.Fprint(c.Out, r.Csv)
			case md:
				fmt.Fprint(c.Out, r.Markdown)
			default:
				c.PrintReport(r.Report, j)
			}
			return nil
		})},
	}}
}

// help son las líneas de este área en mctl --help.
const help = `  find  IP|MAC|NOMBRE           (busca en la evidencia de toda la flota; MAC en cualquier notación)
  trace MAC|IP                  (sigue la MAC por las tablas CAM hasta el puerto de acceso)
  path  ORIGEN DESTINO [--svg ARCHIVO]   (camino L3 salto a salto con el tramo L2)
  health interfaces             (interfaces con CRC, errores, drops, err-disabled, half duplex)
  fleet summary | flash [--need 1.2G] | inventory [--csv|--md]
        (flota = última salida de cada equipo en outputs/; todas con --dir CARPETA y --json)`
