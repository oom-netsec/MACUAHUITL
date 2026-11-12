package calc

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func printCalc(c *cli.Env, r *v1.CalcResult, asJSON bool) {
	if asJSON {
		fmt.Fprintln(c.Out, r.Json)
		return
	}
	fmt.Fprintln(c.Out, r.Text)
}

// calcCmd arma un subcomando de calc: registra --json, pide el resultado y lo imprime.
func calcCmd(name string, setup func(*flag.FlagSet), do func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error)) func(*cli.Env, []string) error {
	return func(c *cli.Env, args []string) error {
		var asJSON bool
		fs, err := cli.Flags("calc "+name, args, func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "salida JSON")
			if setup != nil {
				setup(fs)
			}
		})
		if err != nil {
			return err
		}
		r, err := do(c, fs)
		if err != nil {
			return err
		}
		printCalc(c, r, asJSON)
		return nil
	}
}

// Area registra "calc ..." (todas con --json).
func Area() cli.Area {
	var mac, by, bw, window, convert, fiber string
	var mtu, mss, conn, splices, maxPaths int
	var inner6, acm, dmed, relax bool
	var rtt, loss, tx, rx, km, lossKm, connLoss, spliceLoss, margin float64
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "calc subnet", Run: calcCmd("subnet", nil, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
			if fs.NArg() == 0 {
				return nil, errors.New("uso: mctl calc subnet PREFIJO | DIRECCIÓN MÁSCARA [--json]")
			}
			r, err := v1.NewCalcServiceClient(c.Conn).Subnet(context.Background(), &v1.SubnetRequest{Prefix: strings.Join(fs.Args(), " ")})
			return r.GetResult(), err
		})},
		{Name: "calc vlsm", Run: calcCmd("vlsm", nil, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
			if fs.NArg() < 2 {
				return nil, errors.New("uso: mctl calc vlsm RED [NOMBRE=]HOSTS... [--json]")
			}
			var needs []*v1.VlsmNeed
			for _, a := range fs.Args()[1:] {
				name, hosts, ok := strings.Cut(a, "=")
				if !ok {
					name, hosts = "", a
				}
				n, err := strconv.ParseUint(hosts, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("necesidad %q inválida: usa NOMBRE=HOSTS o HOSTS", a)
				}
				needs = append(needs, &v1.VlsmNeed{Name: name, Hosts: n})
			}
			r, err := v1.NewCalcServiceClient(c.Conn).Vlsm(context.Background(), &v1.VlsmRequest{Network: fs.Arg(0), Needs: needs})
			return r.GetResult(), err
		})},
		{Name: "calc summarize", Run: calcCmd("summarize", nil, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
			r, err := v1.NewCalcServiceClient(c.Conn).Summarize(context.Background(), &v1.SummarizeRequest{Prefixes: fs.Args()})
			return r.GetResult(), err
		})},
		{Name: "calc wildcard", Run: calcCmd("wildcard", nil, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
			req := &v1.WildcardRequest{}
			switch fs.NArg() {
			case 1:
				req.Value = fs.Arg(0)
			case 2:
				req.Address, req.Value = fs.Arg(0), fs.Arg(1)
			default:
				return nil, errors.New("uso: mctl calc wildcard PREFIJO|MÁSCARA|WILDCARD | DIRECCIÓN WILDCARD [--json]")
			}
			r, err := v1.NewCalcServiceClient(c.Conn).Wildcard(context.Background(), req)
			return r.GetResult(), err
		})},
		{Name: "calc ipv6", Run: calcCmd("ipv6", func(fs *flag.FlagSet) {
			fs.StringVar(&mac, "mac", "", "MAC para armar la EUI-64")
		}, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
			r, err := v1.NewCalcServiceClient(c.Conn).Ipv6(context.Background(), &v1.Ipv6Request{Address: fs.Arg(0), Mac: mac})
			return r.GetResult(), err
		})},
		{Name: "calc mtu", Run: calcCmd("mtu", func(fs *flag.FlagSet) {
			fs.IntVar(&mtu, "mtu", 1500, "MTU IP física")
			fs.BoolVar(&inner6, "ipv6", false, "tráfico interno IPv6 (MSS = MTU - 60)")
		}, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
			if mtu < 0 {
				return nil, fmt.Errorf("MTU %d inválida", mtu)
			}
			r, err := v1.NewCalcServiceClient(c.Conn).Mtu(context.Background(), &v1.MtuRequest{Physical: uint32(mtu), Layers: fs.Args(), InnerIpv6: inner6})
			return r.GetResult(), err
		})},
		{Name: "calc tcp", Run: calcCmd("tcp", func(fs *flag.FlagSet) {
			fs.StringVar(&bw, "bw", "", "ancho de banda (1g, 100m)")
			fs.Float64Var(&rtt, "rtt", 0, "RTT en ms")
			fs.StringVar(&window, "window", "", "ventana en bytes (64k, 4m)")
			fs.Float64Var(&loss, "loss", 0, "pérdida en %")
			fs.IntVar(&mss, "mss", 0, "MSS (1460 por defecto)")
		}, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
			if mss < 0 {
				return nil, fmt.Errorf("MSS %d inválido", mss)
			}
			r, err := v1.NewCalcServiceClient(c.Conn).Tcp(context.Background(), &v1.TcpRequest{Bandwidth: bw, RttMs: rtt, Window: window, LossPercent: loss, Mss: uint32(mss)})
			return r.GetResult(), err
		})},
		{Name: "calc dscp", Run: calcCmd("dscp", func(fs *flag.FlagSet) {
			fs.StringVar(&by, "by", "", "campo: name, dscp, binary, tos, precedence, cos, exp")
		}, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
			r, err := v1.NewCalcServiceClient(c.Conn).Dscp(context.Background(), &v1.DscpRequest{Query: fs.Arg(0), Field: by})
			return r.GetResult(), err
		})},
		{Name: "calc optics", Run: func(c *cli.Env, args []string) error {
			var overload optFloat // por corrida: la bandera no debe arrastrar valor entre dos run()
			return calcCmd("optics", func(fs *flag.FlagSet) {
				fs.StringVar(&convert, "convert", "", "solo convertir: -3dBm o 0.5mW")
				fs.Float64Var(&tx, "tx", 0, "potencia Tx mínima (dBm)")
				fs.Float64Var(&rx, "rx", 0, "sensibilidad Rx (dBm)")
				fs.Var(&overload, "overload", "saturación del receptor (dBm)")
				fs.Float64Var(&km, "km", 0, "distancia en km")
				fs.StringVar(&fiber, "fiber", "smf-1310", "smf-1310, smf-1550, mmf-850, mmf-1300")
				fs.Float64Var(&lossKm, "loss-km", 0, "pérdida por km (reemplaza la de la fibra)")
				fs.IntVar(&conn, "conn", 2, "conectores")
				fs.Float64Var(&connLoss, "conn-loss", 0.5, "pérdida por conector (dB)")
				fs.IntVar(&splices, "splices", 0, "empalmes")
				fs.Float64Var(&spliceLoss, "splice-loss", 0.1, "pérdida por empalme (dB)")
				fs.Float64Var(&margin, "margin", 3, "margen exigido (dB)")
			}, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
				if conn < 0 || splices < 0 {
					return nil, errors.New("conectores y empalmes no pueden ser negativos")
				}
				r, err := v1.NewCalcServiceClient(c.Conn).Optics(context.Background(), &v1.OpticsRequest{Convert: convert, TxDbm: tx, RxSensitivityDbm: rx, RxOverloadDbm: overload.p, Km: km, Fiber: fiber,
					LossPerKm: lossKm, Connectors: uint32(conn), ConnectorLossDb: connLoss, Splices: uint32(splices), SpliceLossDb: spliceLoss, MarginDb: margin})
				return r.GetResult(), err
			})(c, args)
		}},
		{Name: "calc bgp", Run: func(c *cli.Env, args []string) error {
			var routes cli.List
			return calcCmd("bgp", func(fs *flag.FlagSet) {
				fs.Var(&routes, "route", "ruta: name=A,weight=N (0 = por defecto: 32768 si local),lp=N,local,path=65001 65002,origin=i|e|?,med=N,ebgp,igp=N,rid=IP,originator=IP,cluster=N,nbr=IP,age=SEG,unreachable (repetible, en orden de llegada)")
				fs.BoolVar(&acm, "always-compare-med", false, "bgp always-compare-med")
				fs.BoolVar(&dmed, "deterministic-med", false, "bgp deterministic-med")
				fs.BoolVar(&relax, "multipath-relax", false, "bgp bestpath as-path multipath-relax")
				fs.IntVar(&maxPaths, "maximum-paths", 0, "maximum-paths")
			}, func(c *cli.Env, fs *flag.FlagSet) (*v1.CalcResult, error) {
				req := &v1.BgpRequest{AlwaysCompareMed: acm, DeterministicMed: dmed, MultipathRelax: relax, MaximumPaths: uint32(max(maxPaths, 0))}
				for _, s := range routes {
					rt, err := parseRoute(s)
					if err != nil {
						return nil, err
					}
					req.Routes = append(req.Routes, rt)
				}
				r, err := v1.NewCalcServiceClient(c.Conn).Bgp(context.Background(), req)
				return r.GetResult(), err
			})(c, args)
		}},
	}}
}

// optFloat es una bandera float opcional: nil si no se escribió.
type optFloat struct{ p *float64 }

func (o *optFloat) String() string {
	if o.p == nil {
		return ""
	}
	return strconv.FormatFloat(*o.p, 'f', -1, 64)
}

func (o *optFloat) Set(s string) error {
	v, err := strconv.ParseFloat(s, 64)
	o.p = &v
	return err
}

// parseRoute lee clave=valor separados por comas; las comas dentro de {..} son del AS_SET.
func parseRoute(s string) (*v1.BgpRoute, error) {
	r := &v1.BgpRoute{}
	var fields []string
	depth, start := 0, 0
	for i, ch := range s {
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				fields = append(fields, s[start:i])
				start = i + 1
			}
		}
	}
	fields = append(fields, s[start:])
	u32 := func(k, v string) (uint32, error) {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("ruta %q: %s=%q no es un número", s, k, v)
		}
		return uint32(n), nil
	}
	for _, f := range fields {
		k, v, _ := strings.Cut(strings.TrimSpace(f), "=")
		var err error
		var n uint32
		switch k {
		case "name":
			r.Name = v
		case "weight":
			r.Weight, err = u32(k, v)
		case "lp":
			n, err = u32(k, v)
			r.LocalPref = &n
		case "med":
			n, err = u32(k, v)
			r.Med = &n
		case "igp":
			r.IgpMetric, err = u32(k, v)
		case "cluster":
			r.ClusterListLength, err = u32(k, v)
		case "age":
			n, err = u32(k, v)
			r.AgeSeconds = int64(n)
		case "local":
			r.LocallyOriginated = true
		case "ebgp":
			r.Ebgp = true
		case "unreachable":
			r.NextHopUnreachable = true
		case "path":
			r.AsPath = v
		case "origin":
			r.Origin = v
		case "rid":
			r.RouterId = v
		case "originator":
			r.OriginatorId = v
		case "nbr":
			r.Neighbor = v
		case "":
		default:
			return nil, fmt.Errorf("ruta %q: clave %q desconocida", s, k)
		}
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

// help son las líneas de este área en mctl --help.
const help = `  calc  subnet PREFIJO | vlsm RED [NOMBRE=]HOSTS... | summarize PREFIJO... | wildcard [DIRECCIÓN] VALOR
        ipv6 [DIRECCIÓN] [--mac MAC] | mtu CAPA... [--mtu 1500] [--ipv6] | tcp --bw 1g --rtt MS [--window 64k] [--loss %]
        dscp [CONSULTA] [--by CAMPO] | optics --tx DBM --rx DBM --km KM [--fiber F] | optics --convert -3dBm
        bgp --route name=A,lp=200,path=65001,med=10,ebgp,rid=IP... [--deterministic-med] [--always-compare-med]
        (todas con --json)`
