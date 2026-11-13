package visibility

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// topo build JOB|CARPETA [--pcap ARCHIVO] [--svg ARCHIVO] [--json]
func topoBuild(c *cli.Env, args []string) error {
	var pcap, svg string
	var asJSON bool
	fs, err := cli.Flags("topo build", args, func(fs *flag.FlagSet) {
		fs.StringVar(&pcap, "pcap", "", "captura con tramas CDP/LLDP")
		fs.StringVar(&svg, "svg", "", "escribe el dibujo en este archivo")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 0 && pcap == "") {
		return errors.New("uso: mctl topo build TRABAJO|CARPETA [--pcap ARCHIVO] [--svg ARCHIVO] [--json]")
	}
	req := &v1.BuildTopologyRequest{}
	if a := fs.Arg(0); a != "" {
		if st, err := os.Stat(a); err == nil && st.IsDir() {
			if req.Dir, err = filepath.Abs(a); err != nil {
				return err
			}
		} else {
			req.JobId = a
		}
	}
	if pcap != "" {
		if req.PcapPath, err = filepath.Abs(pcap); err != nil {
			return err
		}
	}
	r, err := v1.NewVisibilityServiceClient(c.Conn).BuildTopology(context.Background(), req)
	if err != nil {
		return err
	}
	if svg != "" {
		if err := os.WriteFile(svg, []byte(r.Svg), 0o600); err != nil {
			return err
		}
	}
	c.PrintReport(r.Report, asJSON)
	return nil
}

type snmpFlags struct {
	cred, version, auth, priv string
	port, timeout             int
	asJSON                    bool
}

func (f *snmpFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.cred, "cred", "", "ID de la credencial en la bóveda (v2c: contraseña = comunidad; v3: usuario, contraseña = auth, enable = priv)")
	fs.StringVar(&f.version, "v", "2c", "versión: 2c o 3")
	fs.StringVar(&f.auth, "auth", "SHA", "v3: SHA, SHA224, SHA256, SHA384, SHA512")
	fs.StringVar(&f.priv, "priv", "AES", "v3: AES, AES192, AES256")
	fs.IntVar(&f.port, "port", 0, "puerto (161 por defecto)")
	fs.IntVar(&f.timeout, "timeout", 0, "milisegundos por intento")
	fs.BoolVar(&f.asJSON, "json", false, "salida JSON")
}

func (f *snmpFlags) target(host string) *v1.SnmpTarget {
	return &v1.SnmpTarget{Host: host, Port: uint32(f.port), Version: f.version, CredentialId: f.cred, AuthProtocol: f.auth, PrivProtocol: f.priv, TimeoutMs: int32(f.timeout)}
}

func snmpGet(c *cli.Env, args []string) error {
	var sf snmpFlags
	fs, err := cli.Flags("snmp get", args, sf.register)
	if err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("uso: mctl snmp get HOST OID... --cred ID [-v 3 --auth SHA --priv AES]")
	}
	r, err := v1.NewVisibilityServiceClient(c.Conn).SnmpGet(context.Background(), &v1.SnmpGetRequest{Target: sf.target(fs.Arg(0)), Oids: fs.Args()[1:]})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, sf.asJSON)
	return nil
}

func snmpWalk(c *cli.Env, args []string) error {
	var sf snmpFlags
	var bulk bool
	var limit int
	fs, err := cli.Flags("snmp walk", args, func(fs *flag.FlagSet) {
		sf.register(fs)
		fs.BoolVar(&bulk, "bulk", false, "GetBulk en vez de GetNext")
		fs.IntVar(&limit, "limit", 0, "máximo de valores (50000 por defecto)")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("uso: mctl snmp walk HOST OID --cred ID [--bulk] [--limit N]")
	}
	r, err := v1.NewVisibilityServiceClient(c.Conn).SnmpWalk(context.Background(), &v1.SnmpWalkRequest{Target: sf.target(fs.Arg(0)), Oid: fs.Arg(1), Bulk: bulk, Limit: int32(limit)})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, sf.asJSON)
	return nil
}

func snmpPoll(c *cli.Env, args []string) error {
	var sf snmpFlags
	var profiles cli.List
	var every, count, secs int
	fs, err := cli.Flags("snmp poll", args, func(fs *flag.FlagSet) {
		sf.register(fs)
		fs.Var(&profiles, "profile", "sistema, interfaces, cpu o memoria (repetible)")
		fs.IntVar(&every, "every", 10, "segundos entre muestras")
		fs.IntVar(&count, "count", 0, "muestras (0 = hasta --for)")
		fs.IntVar(&secs, "for", 0, "segundos (0 = 1 h; máximo 24 h)")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl snmp poll HOST --cred ID [--profile P]... [--every S] [--count N] [--for S]")
	}
	st, err := v1.NewVisibilityServiceClient(c.Conn).SnmpPoll(context.Background(), &v1.SnmpPollRequest{Target: sf.target(fs.Arg(0)), Profiles: profiles, IntervalSeconds: int32(every), Count: int32(count), DurationSeconds: int32(secs)})
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
		if sf.asJSON {
			fmt.Fprintln(c.Out, r.Json)
			continue
		}
		printSample(c, r.Json)
	}
}

func printSample(c *cli.Env, js string) {
	var s struct {
		Time       time.Time
		System     map[string]string
		Interfaces []struct {
			Name, Oper          string
			InBps, OutBps       *float64
			InErrors, OutErrors uint64
		}
		CPU []struct {
			Index                    string
			FiveSec, OneMin, FiveMin uint64
		}
		Memory []struct {
			Name    string
			UsedPct float64
		}
		Errors []string
	}
	if json.Unmarshal([]byte(js), &s) != nil {
		fmt.Fprintln(c.Out, js)
		return
	}
	fmt.Fprintf(c.Out, "== %s %s\n", s.Time.Local().Format("15:04:05"), s.System["sysName"])
	for _, i := range s.Interfaces {
		fmt.Fprintf(c.Out, "  %-24s %-6s in %s  out %s  err %d/%d\n", i.Name, i.Oper, bps(i.InBps), bps(i.OutBps), i.InErrors, i.OutErrors)
	}
	for _, p := range s.CPU {
		fmt.Fprintln(c.Out, cli.T("mctl.visibility.cpu", "index", p.Index, "five", p.FiveSec, "one", p.OneMin, "fivemin", p.FiveMin))
	}
	for _, m := range s.Memory {
		fmt.Fprintln(c.Out, cli.T("mctl.visibility.memory", "name", m.Name, "pct", fmt.Sprintf("%.1f", m.UsedPct)))
	}
	for _, e := range s.Errors {
		fmt.Fprintln(c.Out, cli.T("mctl.common_a.warning_indented", "text", e))
	}
}

func bps(v *float64) string {
	switch {
	case v == nil:
		return "-"
	case *v >= 1e9:
		return fmt.Sprintf("%.2f Gb/s", *v/1e9)
	case *v >= 1e6:
		return fmt.Sprintf("%.2f Mb/s", *v/1e6)
	case *v >= 1e3:
		return fmt.Sprintf("%.1f kb/s", *v/1e3)
	}
	return fmt.Sprintf("%.0f b/s", *v)
}

type listenFlags struct {
	addr      string
	any, save bool
	secs      int
}

func (f *listenFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.addr, "addr", "", "dirección de escucha (IP:PUERTO; puerto alto)")
	fs.BoolVar(&f.any, "any", false, "escuchar en todas las interfaces")
	fs.BoolVar(&f.save, "save", false, "guardar en outputs")
	fs.IntVar(&f.secs, "for", 0, "segundos (0 = 1 h; máximo 24 h)")
}

func snmpTraps(c *cli.Env, args []string) error {
	if len(args) == 0 || args[0] != "listen" {
		return errors.New("uso: mctl snmp traps listen [--addr IP:PUERTO] [--any] [--for S] [--save] [--v3-cred ID --auth SHA --priv AES] [--rate N ...]")
	}
	var lf listenFlags
	var cred, auth, priv string
	var inf cli.IngestFlags
	if _, err := cli.Flags("snmp traps listen", args[1:], func(fs *flag.FlagSet) {
		lf.register(fs)
		inf.Register(fs, "traps_{fecha}_{hora}")
		fs.StringVar(&cred, "v3-cred", "", "credencial USM para traps v3")
		fs.StringVar(&auth, "auth", "SHA", "v3: protocolo de autenticación")
		fs.StringVar(&priv, "priv", "AES", "v3: protocolo de privacidad")
	}); err != nil {
		return err
	}
	dur, err := cli.Int32("for", lf.secs)
	if err != nil {
		return err
	}
	v, err := inf.Values()
	if err != nil {
		return err
	}
	st, err := v1.NewVisibilityServiceClient(c.Conn).SnmpTraps(context.Background(), &v1.SnmpTrapsRequest{Addr: lf.addr, AllowAny: lf.any, DurationSeconds: dur, Save: lf.save,
		V3CredentialId: cred, AuthProtocol: auth, PrivProtocol: priv, NameTemplate: inf.Name, Format: inf.Format,
		RatePerSource: v.Rate, BurstPerSource: v.Burst, RateGlobal: v.RateG, BurstGlobal: v.BurstG, QueueSize: v.Queue, RotateMb: v.RotMB, RotateMinutes: v.RotMin, MaxFiles: v.MaxFiles})
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
			fmt.Fprintln(c.Out, cli.T("mctl.common_a.new_file", "path", r.RotatedPath))
		case r.Listening != "":
			listening(c, "traps", r.Listening, r.OutputPath)
		default:
			fmt.Fprintln(c.Out, r.Json)
		}
	}
}

func listening(c *cli.Env, what, addr, out string) {
	code := "mctl.visibility.listening"
	if out != "" {
		code = "mctl.visibility.listening_saving"
	}
	fmt.Fprintln(c.Out, cli.T(code, "what", cli.T("mctl.visibility.what_"+what), "addr", addr, "path", out))
}

func flowsListen(c *cli.Env, args []string) error {
	var lf listenFlags
	var top, every int
	var asJSON bool
	var inf cli.IngestFlags
	if _, err := cli.Flags("flows listen", args, func(fs *flag.FlagSet) {
		lf.register(fs)
		inf.Register(fs, "flujos_{fecha}_{hora}")
		fs.IntVar(&top, "top", 10, "elementos por tabla")
		fs.IntVar(&every, "every", 10, "segundos entre resúmenes")
		fs.BoolVar(&asJSON, "json", false, "resúmenes en JSON")
	}); err != nil {
		return err
	}
	dur, err := cli.Int32("for", lf.secs)
	if err != nil {
		return err
	}
	v, err := inf.Values()
	if err != nil {
		return err
	}
	topN, err := cli.Int32("top", top)
	if err != nil {
		return err
	}
	everyN, err := cli.Int32("every", every)
	if err != nil {
		return err
	}
	st, err := v1.NewVisibilityServiceClient(c.Conn).Flows(context.Background(), &v1.FlowsRequest{Addr: lf.addr, AllowAny: lf.any, DurationSeconds: dur, Save: lf.save, Top: topN, EverySeconds: everyN,
		NameTemplate: inf.Name, Format: inf.Format,
		RatePerSource: v.Rate, BurstPerSource: v.Burst, RateGlobal: v.RateG, BurstGlobal: v.BurstG, QueueSize: v.Queue, RotateMb: v.RotMB, RotateMinutes: v.RotMin, MaxFiles: v.MaxFiles})
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
			fmt.Fprintln(c.Out, cli.T("mctl.common_a.new_file", "path", r.RotatedPath))
		case r.Listening != "":
			listening(c, "flows", r.Listening, r.OutputPath)
		case asJSON:
			fmt.Fprintln(c.Out, r.Json)
		default:
			printFlows(c, r.Json, r.Final)
		}
	}
}

type counter struct {
	Key                   string
	Bytes, Packets, Flows uint64
}

func printFlows(c *cli.Env, js string, final bool) {
	var s struct {
		Flows, Bytes, Errors                     uint64
		Talkers, Conversations, Ports, Protocols []counter
		Exporters                                []struct {
			Exporter             string
			Flows, Bytes, Errors uint64
		}
		LastError string
	}
	if json.Unmarshal([]byte(js), &s) != nil {
		fmt.Fprintln(c.Out, js)
		return
	}
	fmt.Fprintln(c.Out, cli.T("mctl.visibility.flows_line", "time", time.Now().Format("15:04:05"), "flows", s.Flows, "bytes", s.Bytes, "errors", s.Errors))
	if !final {
		return
	}
	for _, t := range []struct {
		name string
		rows []counter
	}{{cli.T("mctl.visibility.top_talkers"), s.Talkers}, {cli.T("mctl.visibility.conversations"), s.Conversations}, {cli.T("mctl.visibility.ports"), s.Ports}, {cli.T("mctl.visibility.protocols"), s.Protocols}} {
		if len(t.rows) == 0 {
			continue
		}
		fmt.Fprintf(c.Out, "\n%s:\n", t.name)
		for _, r := range t.rows {
			fmt.Fprintln(c.Out, cli.T("mctl.visibility.flow_row", "key", fmt.Sprintf("%-44s", r.Key), "bytes", fmt.Sprintf("%12d", r.Bytes), "flows", fmt.Sprintf("%8d", r.Flows)))
		}
	}
	for _, e := range s.Exporters {
		fmt.Fprintln(c.Out, cli.T("mctl.visibility.exporter", "name", e.Exporter, "flows", e.Flows, "bytes", e.Bytes, "errors", e.Errors))
	}
	if s.LastError != "" {
		fmt.Fprintln(c.Out, cli.T("mctl.visibility.last_error", "text", s.LastError))
	}
}

type gnmiFlags struct {
	cred, ca, serverName string
	port, timeout        int
	asJSON               bool
}

func (f *gnmiFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&f.cred, "cred", "", "credencial (usuario y contraseña) en la bóveda")
	fs.StringVar(&f.ca, "ca", "", "CA propia en PEM (por defecto las del sistema)")
	fs.StringVar(&f.serverName, "server-name", "", "nombre a verificar en el certificado")
	fs.IntVar(&f.port, "port", 0, "puerto (9339 por defecto)")
	fs.IntVar(&f.timeout, "timeout", 0, "milisegundos")
	fs.BoolVar(&f.asJSON, "json", false, "salida JSON")
}

func (f *gnmiFlags) target(host string) (*v1.GnmiTarget, error) {
	t := &v1.GnmiTarget{Host: host, Port: uint32(f.port), CredentialId: f.cred, ServerName: f.serverName, TimeoutMs: int32(f.timeout)}
	if f.ca != "" {
		p, err := filepath.Abs(f.ca)
		if err != nil {
			return nil, err
		}
		t.CaPath = p
	}
	return t, nil
}

func gnmiGet(c *cli.Env, args []string) error {
	var gf gnmiFlags
	var enc string
	fs, err := cli.Flags("gnmi get", args, func(fs *flag.FlagSet) {
		gf.register(fs)
		fs.StringVar(&enc, "encoding", "", "json_ietf (por defecto), json, proto o ascii")
	})
	if err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("uso: mctl gnmi get HOST RUTA... --cred ID [--ca CA.pem] [--port N]")
	}
	t, err := gf.target(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := v1.NewVisibilityServiceClient(c.Conn).GnmiGet(context.Background(), &v1.GnmiGetRequest{Target: t, Paths: fs.Args()[1:], Encoding: enc})
	if err != nil {
		return err
	}
	c.PrintReport(r.Report, gf.asJSON)
	return nil
}

func gnmiSubscribe(c *cli.Env, args []string) error {
	var gf gnmiFlags
	var mode string
	var every, secs int
	fs, err := cli.Flags("gnmi subscribe", args, func(fs *flag.FlagSet) {
		gf.register(fs)
		fs.StringVar(&mode, "mode", "sample", "sample u on_change")
		fs.IntVar(&every, "every", 10, "segundos entre muestras (sample)")
		fs.IntVar(&secs, "for", 0, "segundos (0 = 1 h; máximo 24 h)")
	})
	if err != nil {
		return err
	}
	if fs.NArg() < 2 {
		return errors.New("uso: mctl gnmi subscribe HOST RUTA... --cred ID [--mode sample|on_change] [--every S] [--for S]")
	}
	t, err := gf.target(fs.Arg(0))
	if err != nil {
		return err
	}
	st, err := v1.NewVisibilityServiceClient(c.Conn).GnmiSubscribe(context.Background(), &v1.GnmiSubscribeRequest{Target: t, Paths: fs.Args()[1:], Mode: mode, IntervalSeconds: int32(every), DurationSeconds: int32(secs)})
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
		fmt.Fprintln(c.Out, r.Json)
	}
}

// help son las líneas de este área en mctl --help.
const help = `  topo  build TRABAJO|CARPETA [--pcap ARCHIVO] [--svg ARCHIVO] [--json]
  snmp  get HOST OID... | walk HOST OID [--bulk] | poll HOST [--profile P]... [--every S] [--count N]
        --cred ID [-v 2c|3 --auth SHA --priv AES] [--port N] [--json]
        traps listen [--addr IP:PUERTO] [--any] [--for S] [--v3-cred ID] [topes y archivo]   (1162 por defecto)
  flows listen [--addr IP:PUERTO] [--any] [--for S] [--top N] [--every S] [--json] [topes y archivo]
        topes y archivo: [--rate N] [--burst N] [--rate-global N] [--burst-global N] [--queue N]
        [--save [--rotate-mb N] [--rotate-min N] [--name PLANTILLA] [--max-files N] [--format texto|crudo|jsonl]]
        en flows el tope cuenta datagramas (no flujos), solo rige con --save (1000/s por exportador y 5000/s global por defecto);
        un datagrama de plantilla v9/IPFIX descartado retrasa la decodificación hasta que el exportador la repita
  gnmi  get|subscribe HOST RUTA... --cred ID [--ca CA.pem] [--port N] [--mode sample|on_change]`

// Area registra los comandos de visibility.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "topo build", Run: topoBuild},
		{Name: "snmp get", Run: snmpGet},
		{Name: "snmp walk", Run: snmpWalk},
		{Name: "snmp poll", Run: snmpPoll},
		{Name: "snmp traps", Run: snmpTraps},
		{Name: "flows listen", Run: flowsListen},
		{Name: "gnmi get", Run: gnmiGet},
		{Name: "gnmi subscribe", Run: gnmiSubscribe},
	}}
}
