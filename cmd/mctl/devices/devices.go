// Package devices son los comandos de equipos conocidos (`mctl devices`) y de la libreta de hosts (`mctl hosts`).
package devices

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// devices [TEXTO] [--json]
func list(c *cli.Env, args []string) error {
	var asJSON bool
	fs, err := cli.Flags("devices", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "salida JSON") })
	if err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("uso: mctl devices [TEXTO] [--json]")
	}
	r, err := v1.NewInventoryServiceClient(c.Conn).ListDevices(context.Background(), &v1.ListDevicesRequest{Query: fs.Arg(0)})
	if err != nil {
		return err
	}
	if asJSON {
		b, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(r)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, string(b))
		return nil
	}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DIRECCIÓN\tNOMBRE\tPLATAFORMA\tVISTO\tORIGEN")
	for _, d := range r.Devices {
		seen := "nunca"
		if d.LastSeenMs > 0 {
			seen = time.UnixMilli(d.LastSeenMs).UTC().Format("2006-01-02 15:04")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", d.GetTarget().GetAddress(), d.Hostname, d.Platform, seen, strings.Join(d.Sources, ","))
	}
	tw.Flush()
	for _, w := range r.Warnings {
		fmt.Fprintf(c.Out, "aviso: %s\n", w)
	}
	return nil
}

const help = `  devices [TEXTO] [--json]
        (equipos conocidos de los trabajos de Patrol, la flota, los respaldos y la libreta de hosts, sin duplicados por dirección; TEXTO filtra por dirección, nombre, plataforma, carpeta o etiqueta)`

// Area registra los comandos de equipos conocidos.
func Area() cli.Area {
	return cli.Area{Usage: help + "\n" + hostsHelp, Commands: []cli.Command{
		{Name: "devices", Run: list},
		{Name: "hosts list", Run: hostsList}, {Name: "hosts add", Run: hostsAdd}, {Name: "hosts edit", Run: hostsEdit},
		{Name: "hosts rm", Run: hostsRm}, {Name: "hosts export", Run: hostsExport}, {Name: "hosts import", Run: hostsImport}, {Name: "hosts template", Run: hostsTemplate},
	}}
}
