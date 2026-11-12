package tools

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

var dnsModes = map[string]v1.DnsMode{
	"query": v1.DnsMode_DNS_MODE_QUERY, "transport": v1.DnsMode_DNS_MODE_TRANSPORT, "hygiene": v1.DnsMode_DNS_MODE_HYGIENE,
	"exposure": v1.DnsMode_DNS_MODE_EXPOSURE, "trace": v1.DnsMode_DNS_MODE_TRACE, "zone": v1.DnsMode_DNS_MODE_ZONE, "dnssec": v1.DnsMode_DNS_MODE_DNSSEC,
}

func printReport(c *cli.Env, r *v1.ToolReport, asJSON bool) {
	if asJSON {
		fmt.Fprintln(c.Out, r.Json)
		return
	}
	fmt.Fprintln(c.Out, r.Text)
}

func pcapAnalyze(c *cli.Env, args []string) error {
	var top int
	var asJSON bool
	fs, err := cli.Flags("pcap analyze", args, func(fs *flag.FlagSet) {
		fs.IntVar(&top, "top", 0, "elementos por lista")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("uso: mctl pcap analyze ARCHIVO [--top N] [--json]")
	}
	p, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := v1.NewToolsServiceClient(c.Conn).AnalyzePcap(context.Background(), &v1.AnalyzePcapRequest{Path: p, Top: int32(top)})
	if err != nil {
		return err
	}
	printReport(c, r.Report, asJSON)
	return nil
}

func dns(mode string) func(*cli.Env, []string) error {
	return func(c *cli.Env, args []string) error {
		var servers cli.List
		var typ, dkim string
		var deep, dnssec, asJSON bool
		var timeout int
		fs, err := cli.Flags("dns "+mode, args, func(fs *flag.FlagSet) {
			fs.Var(&servers, "s", "servidor (udp://, tcp://, tls://, https:// o IP; repetible)")
			fs.StringVar(&typ, "t", "", "tipo de registro")
			fs.StringVar(&dkim, "dkim", "", "selector DKIM")
			fs.BoolVar(&deep, "deep", false, "autoriza contactar raíces, TLD y autoritativos")
			fs.BoolVar(&dnssec, "dnssec", false, "pide registros DNSSEC")
			fs.BoolVar(&asJSON, "json", false, "salida JSON compacta")
			fs.IntVar(&timeout, "timeout", 0, "milisegundos por consulta")
		})
		if err != nil {
			return err
		}
		r, err := v1.NewToolsServiceClient(c.Conn).Dns(context.Background(), &v1.DnsRequest{Mode: dnsModes[mode], Name: fs.Arg(0), Type: typ, Servers: servers, Deep: deep,
			Dnssec: dnssec, DkimSelector: dkim, TimeoutMs: int32(timeout)})
		if err != nil {
			return err
		}
		printReport(c, r.Report, asJSON)
		return nil
	}
}

func tlsInspect(c *cli.Env, args []string) error {
	var sni string
	var timeout int
	var asJSON bool
	fs, err := cli.Flags("tls inspect", args, func(fs *flag.FlagSet) {
		fs.StringVar(&sni, "sni", "", "nombre SNI (por defecto el host)")
		fs.IntVar(&timeout, "timeout", 0, "milisegundos por handshake")
		fs.BoolVar(&asJSON, "json", false, "salida JSON compacta")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("uso: mctl tls inspect HOST[:PUERTO] [--sni NOMBRE]")
	}
	host, port := fs.Arg(0), uint64(443)
	h, p, hasPort := "", "", false
	if strings.HasPrefix(host, "[") { // [IPv6]:puerto
		h, p, hasPort = strings.Cut(strings.TrimPrefix(host, "["), "]:")
	} else if strings.Count(host, ":") == 1 {
		h, p, hasPort = strings.Cut(host, ":")
	}
	if hasPort {
		if port, err = strconv.ParseUint(p, 10, 16); err != nil {
			return fmt.Errorf("puerto inválido %q", p)
		}
		host = h
	}
	host = strings.Trim(host, "[]")
	r, err := v1.NewToolsServiceClient(c.Conn).InspectTls(context.Background(), &v1.InspectTlsRequest{Host: host, Port: uint32(port), Sni: sni, TimeoutMs: int32(timeout)})
	if err != nil {
		return err
	}
	printReport(c, r.Report, asJSON)
	return nil
}

func syslogListen(c *cli.Env, args []string) error {
	var addr string
	var tcp, any, save bool
	var secs int
	var inf cli.IngestFlags
	if _, err := cli.Flags("syslog listen", args, func(fs *flag.FlagSet) {
		fs.StringVar(&addr, "addr", "", "dirección de escucha (127.0.0.1:5514 por defecto)")
		fs.BoolVar(&tcp, "tcp", false, "TCP en vez de UDP")
		fs.BoolVar(&any, "any", false, "escuchar en todas las interfaces")
		fs.BoolVar(&save, "save", false, "guardar en outputs/syslog")
		fs.IntVar(&secs, "for", 0, "segundos (0 = 1 h; máximo 24 h)")
		inf.Register(fs, "syslog_{fecha}_{hora}")
	}); err != nil {
		return err
	}
	proto := "udp"
	if tcp {
		proto = "tcp"
	}
	dur, err := cli.Int32("for", secs)
	if err != nil {
		return err
	}
	v, err := inf.Values()
	if err != nil {
		return err
	}
	req := &v1.SyslogRequest{Addr: addr, Protocol: proto, AllowAny: any, Save: save, NameTemplate: inf.Name, Format: inf.Format, DurationSeconds: dur,
		RatePerSource: v.Rate, BurstPerSource: v.Burst, RateGlobal: v.RateG, BurstGlobal: v.BurstG, QueueSize: v.Queue, RotateMb: v.RotMB, RotateMinutes: v.RotMin, MaxFiles: v.MaxFiles}
	st, err := v1.NewToolsServiceClient(c.Conn).Syslog(context.Background(), req)
	if err != nil {
		return err
	}
	for {
		r, err := st.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch {
		case r.Drops != nil:
			cli.PrintDrops(c.Out, r.Drops)
		case r.RotatedPath != "":
			fmt.Fprintf(c.Out, "archivo nuevo: %s\n", r.RotatedPath)
		case r.Listening != "":
			fmt.Fprintf(c.Out, "escuchando en %s/%s", r.Listening, proto)
			if r.OutputPath != "" {
				fmt.Fprintf(c.Out, " (guardando en %s)", r.OutputPath)
			}
			fmt.Fprintln(c.Out)
		default:
			fmt.Fprintln(c.Out, r.Json)
		}
	}
}

// help son las líneas de este área en mctl --help.
const help = `  pcap  analyze ARCHIVO [--top N] [--json]
  dns   query|transport|hygiene|exposure NOMBRE [-t TIPO] [-s SERVIDOR]... [--dnssec] [--dkim SEL]
        trace|zone|dnssec NOMBRE --deep   (contacta raíces y autoritativos; queda auditado)
  tls   inspect HOST[:PUERTO] [--sni NOMBRE]
  syslog listen [--addr IP:PUERTO] [--tcp] [--any] [--for SEGUNDOS] [--rate N] [--burst N] [--rate-global N] [--burst-global N] [--queue N]
        [--save [--rotate-mb N] [--rotate-min N] [--name PLANTILLA] [--max-files N] [--format texto|crudo|jsonl]]`

// Area registra pcap analyze, dns, tls y syslog.
func Area() cli.Area {
	cmds := []cli.Command{
		{Name: "pcap analyze", Run: pcapAnalyze},
		{Name: "tls inspect", Run: tlsInspect},
		{Name: "syslog listen", Run: syslogListen},
	}
	for m := range dnsModes {
		cmds = append(cmds, cli.Command{Name: "dns " + m, Run: dns(m)})
	}
	return cli.Area{Usage: help, Commands: cmds}
}
