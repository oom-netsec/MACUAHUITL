package diag

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

var diagToolEnum = map[string]v1.DiagTool{"ping": v1.DiagTool_DIAG_TOOL_PING, "traceroute": v1.DiagTool_DIAG_TOOL_TRACEROUTE,
	"nmap": v1.DiagTool_DIAG_TOOL_NMAP, "iperf3": v1.DiagTool_DIAG_TOOL_IPERF3, "pcap": v1.DiagTool_DIAG_TOOL_PCAP}

func diag(tool string) func(*cli.Env, []string) error {
	return func(c *cli.Env, args []string) error {
		var opts cli.List
		var out string
		fs, err := cli.Flags("diag "+tool, args, func(fs *flag.FlagSet) {
			fs.Var(&opts, "o", "opción clave=valor (repetible)")
			fs.StringVar(&out, "out", "", "carpeta de salida")
		})
		if err != nil {
			return err
		}
		req := &v1.RunRequest{Tool: diagToolEnum[tool], OutputDir: out, Options: map[string]string{}}
		for _, a := range fs.Args() {
			req.Targets = append(req.Targets, &v1.Target{Address: a})
		}
		for _, o := range opts {
			k, v, ok := strings.Cut(o, "=")
			if !ok {
				return fmt.Errorf("opción %q: usa clave=valor", o)
			}
			req.Options[k] = v
		}
		st, err := v1.NewDiagServiceClient(c.Conn).Run(context.Background(), req)
		if err != nil {
			return err
		}
		for {
			r, err := st.Recv()
			if err != nil {
				return err
			}
			if r.Done {
				fmt.Fprintf(c.Out, "guardado en %s (código de salida %d)\n", r.OutputPath, r.ExitCode)
				if r.ExitCode != 0 {
					return fmt.Errorf("%s terminó con código %d", tool, r.ExitCode)
				}
				return nil
			}
			fmt.Fprintln(c.Out, r.OutputLine)
		}
	}
}

func interfaces(c *cli.Env, args []string) error {
	if _, err := cli.Flags("diag interfaces", args, nil); err != nil {
		return err
	}
	r, err := v1.NewDiagServiceClient(c.Conn).ListInterfaces(context.Background(), &v1.ListInterfacesRequest{})
	if err != nil {
		return err
	}
	for _, i := range r.Interfaces {
		st := "abajo"
		if i.Up {
			st = "arriba"
		}
		fmt.Fprintf(c.Out, "%s  %s  %s  %s\n", i.Name, st, i.HardwareAddr, strings.Join(i.Addresses, " "))
	}
	return nil
}

// help son las líneas de este área en mctl --help.
const help = `  diag  ping|traceroute|nmap|iperf3|pcap [DESTINO] [-o clave=valor]... [--out CARPETA]
        interfaces   (interfaces locales, sin tráfico de red)`

// Area registra "diag HERRAMIENTA".
func Area() cli.Area {
	var cmds []cli.Command
	for _, tool := range []string{"ping", "traceroute", "nmap", "iperf3", "pcap"} {
		cmds = append(cmds, cli.Command{Name: "diag " + tool, Run: diag(tool)})
	}
	cmds = append(cmds, cli.Command{Name: "diag interfaces", Run: interfaces})
	return cli.Area{Usage: help, Commands: cmds}
}
