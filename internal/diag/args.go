package diag

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type Tool string

const (
	Ping       Tool = "ping"
	Traceroute Tool = "traceroute"
	Nmap       Tool = "nmap"
	Iperf3     Tool = "iperf3"
	Pcap       Tool = "pcap"
)

// Request es lo único que la UI o mctl pueden pedir: no existe una línea de comandos libre.
type Request struct {
	Tool      Tool
	Targets   []string
	Options   map[string]string
	OutputDir string
}

var (
	hostRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]{0,252}[A-Za-z0-9])?$`)
	portsRe = regexp.MustCompile(`^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$`)
	ifaceRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:\-]{0,31}$`)
	intRe   = regexp.MustCompile(`^[0-9]{1,6}$`)
	decRe   = regexp.MustCompile(`^[0-9]{1,4}(\.[0-9]{1,3})?$`)
)

// target valida un destino: IP, nombre DNS o (si cidr) un prefijo. Nunca empieza con "-".
func target(s string, cidr bool) error {
	if s == "" || s[0] == '-' {
		return fmt.Errorf("destino %q inválido", s)
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		if !cidr {
			return fmt.Errorf("%s no acepta rangos CIDR", s)
		}
		if p.Addr().IsValid() {
			return nil
		}
	}
	if strings.Contains(s, "/") {
		return fmt.Errorf("prefijo %q inválido", s)
	}
	if !hostRe.MatchString(s) {
		return fmt.Errorf("destino %q no es IP, nombre ni CIDR", s)
	}
	return nil
}

type opts struct {
	m    map[string]string
	used map[string]bool
	err  error
}

func (o *opts) str(key string, allowed ...string) (string, bool) {
	v, ok := o.m[key]
	if !ok {
		return "", false
	}
	o.used[key] = true
	if len(allowed) > 0 {
		for _, a := range allowed {
			if v == a {
				return v, true
			}
		}
		o.fail("%s debe ser uno de %s", key, strings.Join(allowed, "|"))
		return "", false
	}
	return v, true
}

// num acepta solo dígitos (y un decimal para interval): nada de signos, exponentes ni
// hexadecimal, que las herramientas rechazan o que empezarían con "-".
func (o *opts) num(key string, lo, hi float64) (string, bool) {
	v, ok := o.m[key]
	if !ok {
		return "", false
	}
	o.used[key] = true
	re := intRe
	if key == "interval" {
		re = decRe
	}
	f, err := strconv.ParseFloat(v, 64)
	if !re.MatchString(v) || err != nil || f < lo || f > hi {
		o.fail("%s debe ser un número entre %g y %g", key, lo, hi)
		return "", false
	}
	return v, true
}

func (o *opts) boolean(key string) bool {
	v, ok := o.m[key]
	if ok {
		o.used[key] = true
	}
	return v == "true" || v == "1"
}

func (o *opts) fail(format string, a ...any) {
	if o.err == nil {
		o.err = fmt.Errorf(format, a...)
	}
}

func (o *opts) done() error {
	if o.err != nil {
		return o.err
	}
	for k := range o.m {
		if !o.used[k] {
			return fmt.Errorf("opción %q no existe para esta herramienta", k)
		}
	}
	return nil
}

func one(r Request, cidr bool) (string, error) {
	if len(r.Targets) != 1 {
		return "", errors.New("se necesita exactamente un destino")
	}
	return r.Targets[0], target(r.Targets[0], cidr)
}

// Build arma binario y argv. El archivo de salida de pcap lo agrega Run (-w).
func Build(r Request) (bin string, argv []string, err error) {
	o := &opts{m: r.Options, used: map[string]bool{}}
	switch r.Tool {
	case Ping:
		host, err := one(r, false)
		if err != nil {
			return "", nil, err
		}
		argv = []string{"-n"}
		count, ok := o.num("count", 1, 100)
		if !ok {
			count = "4"
		}
		argv = append(argv, "-c", count)
		if v, ok := o.num("interval", 0.2, 60); ok {
			argv = append(argv, "-i", v)
		}
		if v, ok := o.num("size", 0, 65500); ok {
			argv = append(argv, "-s", v)
		}
		bin, argv = "ping", append(argv, host)
	case Traceroute:
		host, err := one(r, false)
		if err != nil {
			return "", nil, err
		}
		argv = []string{"-n"}
		if v, ok := o.num("max_hops", 1, 64); ok {
			argv = append(argv, "-m", v)
		}
		bin, argv = "traceroute", append(argv, host)
	case Nmap:
		host, err := one(r, true)
		if err != nil {
			return "", nil, err
		}
		scan, _ := o.str("scan", "connect", "syn", "udp", "ping")
		argv = append(argv, map[string]string{"": "-sT", "connect": "-sT", "syn": "-sS", "udp": "-sU", "ping": "-sn"}[scan])
		if v, ok := o.str("ports"); ok {
			if !portsRe.MatchString(v) {
				return "", nil, fmt.Errorf("ports %q inválido; usa 22,80,443-445", v)
			}
			argv = append(argv, "-p", v)
		}
		if v, ok := o.num("timing", 0, 5); ok {
			argv = append(argv, "-T"+v)
		}
		if o.boolean("service_detection") {
			argv = append(argv, "-sV")
		}
		if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
			argv = append(argv, "-6")
		}
		// -n: sin DNS inverso; -oG -: salida parseable por stdout. El núcleo decide el archivo, nunca nmap.
		bin, argv = "nmap", append(argv, "-n", "-oG", "-", host)
	case Iperf3:
		mode, _ := o.str("mode", "client", "server")
		switch mode {
		case "client", "":
			host, err := one(r, false)
			if err != nil {
				return "", nil, fmt.Errorf("iperf3 cliente: %w", err)
			}
			argv = []string{"-c", host}
		case "server":
			argv = []string{"-s"}
		}
		if v, ok := o.num("port", 1, 65535); ok {
			argv = append(argv, "-p", v)
		}
		if mode == "server" {
			o.num("seconds", 1, 600)  // la UI lo manda siempre; el servidor no lo usa
			argv = append(argv, "-1") // una sola prueba y sale
		} else {
			if v, ok := o.num("seconds", 1, 600); ok {
				argv = append(argv, "-t", v)
			}
			if v, ok := o.num("parallel", 1, 64); ok {
				argv = append(argv, "-P", v)
			}
			if o.boolean("reverse") {
				argv = append(argv, "-R")
			}
			if o.boolean("udp") {
				argv = append(argv, "-u")
			}
		}
		bin = "iperf3"
	case Pcap:
		if len(r.Targets) != 0 {
			return "", nil, errors.New("la captura no lleva destino; usa el filtro")
		}
		if r.OutputDir == "" {
			return "", nil, errors.New("la captura necesita una carpeta de salida")
		}
		iface, ok := o.str("interface")
		if !ok || !ifaceRe.MatchString(iface) {
			return "", nil, errors.New("interfaz inválida o ausente")
		}
		argv = []string{"-i", iface}
		if v, ok := o.num("seconds", 1, 3600); ok {
			argv = append(argv, "-a", "duration:"+v)
		}
		if v, ok := o.num("packets", 1, 1000000); ok {
			argv = append(argv, "-c", v)
		}
		if v, ok := o.str("filter"); ok && v != "" {
			argv = append(argv, "-f", v) // un solo argv: sin shell no hay inyección
		}
		bin = "dumpcap"
	default:
		return "", nil, fmt.Errorf("herramienta %q desconocida", r.Tool)
	}
	if err := o.done(); err != nil {
		return "", nil, err
	}
	// Defensa final: ningún valor que venga del usuario puede parecer una bandera.
	for i, a := range argv {
		if strings.HasPrefix(a, "-") && !literalFlags[a] && !(i > 0 && argv[i-1] == "-f") {
			return "", nil, fmt.Errorf("el valor %q parece una bandera", a)
		}
	}
	return bin, argv, nil
}

var literalFlags = map[string]bool{"-n": true, "-c": true, "-i": true, "-s": true, "-m": true, "-sT": true, "-sS": true, "-sU": true, "-sn": true,
	"-p": true, "-T0": true, "-T1": true, "-T2": true, "-T3": true, "-T4": true, "-T5": true, "-sV": true, "-6": true, "-oG": true, "-": true,
	"-P": true, "-R": true, "-u": true, "-t": true, "-1": true, "-a": true, "-f": true, "-w": true}
