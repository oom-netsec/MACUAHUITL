package diag

import (
	"context"
	"flag"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

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
			fs.StringVar(&out, "out", "", "carpeta de salida (debe existir y tener modo 0700)")
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
				return cli.Err("mctl.diag.opt_bad", "opt", o)
			}
			req.Options[k] = v
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		cl := v1.NewDiagServiceClient(c.Conn)
		st, err := cl.Run(ctx, req)
		if err != nil {
			return err
		}
		var runID atomic.Value // string; lo escribe el primer evento
		if tool == "ping" {
			sigs, stopSigs := cli.Interrupts()
			defer stopSigs()
			done := make(chan struct{})
			defer close(done)
			go func() { // Ctrl-C detiene la ejecución en el núcleo y espera el resumen; el segundo corta el stream
				for n := 0; ; {
					select {
					case <-sigs:
						id, _ := runID.Load().(string)
						if n++; n > 1 || id == "" { // el segundo (o uno sin run_id que detener) sale sin esperar al núcleo
							fmt.Fprintln(c.Out, cli.T("mctl.run.ctrlc2"))
							cancel()
							cli.Exit(130)
							return
						}
						fmt.Fprintln(c.Out, cli.T("mctl.diag.ctrlc1"))
						go cl.StopRun(ctx, &v1.StopRunRequest{RunId: id})
					case <-done:
						return
					}
				}
			}()
		}
		var sweep []*v1.SweepPoint
		for {
			r, err := st.Recv()
			if err != nil {
				return err
			}
			if r.RunId != "" { // primer evento: solo el id de la ejecución, para StopRun
				runID.Store(r.RunId)
				continue
			}
			if p := r.SweepPoint; p != nil {
				if len(sweep) == 0 {
					fmt.Fprintln(c.Out, cli.T("mctl.diag.sweep_head"))
				}
				sweep = append(sweep, p)
				fmt.Fprintf(c.Out, "%-9d %-9d %-10d %s\n", p.Size, p.Sent, p.Received, cli.T("mctl.diag.sweep_"+p.Result))
				continue
			}
			if r.Done {
				hdr := ipHeader(req)
				if mtu, frag := estimateMTU(sweep, hdr); frag && hdr == 0 {
					fmt.Fprintln(c.Out, cli.T("mctl.diag.sweep_mtu_unknown"))
				} else if frag {
					fmt.Fprintln(c.Out, cli.T("mctl.diag.sweep_mtu", "mtu", mtu))
				}
				if s := r.PingSummary; s != nil {
					fmt.Fprintln(c.Out, summaryLine(s))
				}
				fmt.Fprintln(c.Out, cli.T("mctl.diag.saved", "path", r.OutputPath, "code", r.ExitCode))
				if r.ExitCode != 0 {
					return cli.Err("mctl.diag.exit_code", "tool", tool, "code", r.ExitCode)
				}
				return nil
			}
			fmt.Fprintln(c.Out, r.OutputLine)
		}
	}
}

func round2(x float64) string { return strconv.FormatFloat(math.Round(x*100)/100, 'f', -1, 64) }

func summaryLine(s *v1.PingSummary) string {
	l := cli.T("mctl.diag.ping_summary", "sent", s.Sent, "recv", s.Received, "loss", round2(s.LossPct))
	if s.Received == 0 {
		return l
	}
	return l + cli.T("mctl.diag.ping_times", "times", round2(s.MinMs)+"/"+round2(s.AvgMs)+"/"+round2(s.MaxMs)+"/"+round2(s.MdevMs))
}

// ipHeader da las cabeceras IP+ICMP (28 en IPv4, 48 en IPv6): family si viene; si no, la IP literal del destino;
// 0 si el destino es un nombre (no se adivina a qué versión resuelve).
func ipHeader(req *v1.RunRequest) int {
	switch req.Options["family"] {
	case "4":
		return 28
	case "6":
		return 48
	}
	if len(req.Targets) > 0 {
		if a, err := netip.ParseAddr(req.Targets[0].Address); err == nil {
			if a.Is4() || a.Is4In6() {
				return 28
			}
			return 48
		}
	}
	return 0
}

// estimateMTU: el mayor tamaño ok antes del primer frag, más hdr; frag es false si no hubo frag o ningún ok antes.
func estimateMTU(pts []*v1.SweepPoint, hdr int) (mtu int, frag bool) {
	best := -1
	for _, p := range pts {
		if p.Result == "frag" {
			if best < 0 {
				return 0, false
			}
			return best + hdr, true
		}
		if p.Result == "ok" {
			best = int(p.Size)
		}
	}
	return 0, false
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
		st := cli.T("mctl.diag.if_down")
		if i.Up {
			st = cli.T("mctl.diag.if_up")
		}
		fmt.Fprintf(c.Out, "%s  %s  %s  %s\n", i.Name, st, i.HardwareAddr, strings.Join(i.Addresses, " "))
	}
	return nil
}

// help son las líneas de este área en mctl --help.
const help = `  diag  ping|traceroute|nmap|iperf3|pcap [DESTINO] [-o clave=valor]... [--out CARPETA]
        --out: la carpeta debe existir y tener modo 0700, como la de Ajustes → Almacenamiento
        interfaces   (interfaces locales, sin tráfico de red)
        ping -o: count (1-100; 1-5 con barrido), continuous, duration (1-3600), timeout (1-60), ttl (1-255), tos (0-255, solo Linux: el ping de Windows no tiene ToS), df, source,
        family (4|6), interval (0.2-60, solo Linux: el ping de Windows no tiene intervalo), size (0-65500), sweep_start, sweep_end, sweep_step (0-65500, máximo 100 tamaños)
        (continuous corre hasta Ctrl-C, que detiene y muestra el resumen; otro Ctrl-C corta ya. Barrido con tabla y MTU estimado:
         mctl diag ping 192.0.2.1 -o df=true -o sweep_start=1200 -o sweep_end=1500 -o sweep_step=50)
        nmap -o: scan, ports, timing, service_detection, skip_discovery`

// Area registra "diag HERRAMIENTA".
func Area() cli.Area {
	var cmds []cli.Command
	for _, tool := range []string{"ping", "traceroute", "nmap", "iperf3", "pcap"} {
		cmds = append(cmds, cli.Command{Name: "diag " + tool, Run: diag(tool)})
	}
	cmds = append(cmds, cli.Command{Name: "diag interfaces", Run: interfaces})
	return cli.Area{Usage: help, Commands: cmds}
}
