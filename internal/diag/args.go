package diag

import (
	"fmt"
	"net/netip"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ifaces"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
	// winIfaceRe: lo que dumpcap -D da en Windows: índice o \Device\NPF_{GUID} (y el loopback de Npcap). Nunca empieza con «-».
	winIfaceRe = regexp.MustCompile(`^([0-9]{1,3}|\\Device\\NPF_(\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}|Loopback))$`)
	intRe      = regexp.MustCompile(`^[0-9]{1,6}$`)
	decRe      = regexp.MustCompile(`^[0-9]{1,4}(\.[0-9]{1,3})?$`)
)

// target valida un destino: IP, nombre DNS o (si cidr) un prefijo. Nunca empieza con "-".
func target(s string, cidr bool) error {
	if s == "" || s[0] == '-' {
		return i18n.New("diag.err.target_bad", i18n.A("target", s))
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		if !cidr {
			return i18n.New("diag.err.no_cidr", i18n.A("target", s))
		}
		if p.Addr().IsValid() {
			return nil
		}
	}
	if strings.Contains(s, "/") {
		return i18n.New("diag.err.prefix_bad", i18n.A("prefix", s))
	}
	if !hostRe.MatchString(s) {
		return i18n.New("diag.err.target_kind", i18n.A("target", s))
	}
	return nil
}

type opts struct {
	m    map[string]string
	used map[string]bool
	err  error
	tool Tool
}

// validOptions son las claves que buildPlan lee por herramienta, ordenadas: se listan cuando llega una desconocida.
// Una prueba cruza esta tabla con buildPlan para que no se desincronice.
var validOptions = map[Tool][]string{
	Ping:       {"continuous", "count", "df", "duration", "family", "interval", "size", "source", "sweep_end", "sweep_start", "sweep_step", "timeout", "tos", "ttl"},
	Traceroute: {"max_hops"},
	Nmap:       {"ports", "scan", "service_detection", "skip_discovery", "timing"},
	Iperf3:     {"bind", "mode", "parallel", "port", "reverse", "seconds", "udp"},
	Pcap:       {"filter", "interface", "packets", "seconds"},
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
		o.fail(i18n.New("diag.err.one_of", i18n.A("key", key, "values", strings.Join(allowed, "|"))))
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
		o.fail(i18n.New("diag.err.number", i18n.A("key", key, "lo", fmt.Sprintf("%g", lo), "hi", fmt.Sprintf("%g", hi))))
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

// strictBool es como boolean pero solo acepta «true» o «false» (boolean acepta también «1»; no se cambia en este bloque): lo demás es error, no «falso» en silencio.
func (o *opts) strictBool(key string) bool {
	v, ok := o.m[key]
	if !ok {
		return false
	}
	o.used[key] = true
	if v != "true" && v != "false" {
		o.fail(i18n.New("diag.err.bool", i18n.A("key", key, "value", v)))
	}
	return v == "true"
}

func (o *opts) fail(err error) {
	if o.err == nil {
		o.err = err
	}
}

func (o *opts) done() error {
	if o.err != nil {
		return o.err
	}
	keys := make([]string, 0, len(o.m))
	for k := range o.m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // el primero (en orden) es el que se reporta: error estable
	for _, k := range keys {
		if !o.used[k] {
			return i18n.New("diag.err.option", i18n.A("key", k, "valid", strings.Join(validOptions[o.tool], ", ")))
		}
	}
	return nil
}

func one(r Request, cidr bool) (string, error) {
	if len(r.Targets) != 1 {
		return "", i18n.New("diag.err.one_target", nil)
	}
	return r.Targets[0], target(r.Targets[0], cidr)
}

// winWaitMs es la espera por respuesta de ping y tracert en Windows (-w, en milisegundos).
const winWaitMs = "2000"

// Build arma binario y argv para el sistema donde corre. El archivo de salida de pcap lo agrega Run (-w).
func Build(r Request) (bin string, argv []string, err error) {
	return build(r, runtime.GOOS == "windows")
}

// buildWindows es Build para Windows; existe aparte para que las pruebas lo corran en cualquier sistema.
func buildWindows(r Request) (string, []string, error) { return build(r, true) }

func build(r Request, win bool) (bin string, argv []string, err error) {
	bin, argv, _, err = buildPlan(r, win)
	return bin, argv, err
}

func buildPlan(r Request, win bool) (bin string, argv []string, plan PingPlan, err error) {
	o := &opts{m: r.Options, used: map[string]bool{}, tool: r.Tool}
	switch r.Tool {
	case Ping:
		host, err := one(r, false)
		if err != nil {
			return "", nil, PingPlan{}, err
		}
		bin = "ping"
		plan, argv = pingArgs(o, host, win)
	case Traceroute:
		host, err := one(r, false)
		if err != nil {
			return "", nil, PingPlan{}, err
		}
		if win { // tracert: -d sin DNS, -h saltos, -w espera
			argv = []string{"-d"}
			if v, ok := o.num("max_hops", 1, 64); ok {
				argv = append(argv, "-h", v)
			}
			bin, argv = "tracert", append(argv, "-w", winWaitMs, host)
			break
		}
		argv = []string{"-n"}
		if v, ok := o.num("max_hops", 1, 64); ok {
			argv = append(argv, "-m", v)
		}
		bin, argv = "traceroute", append(argv, host)
	case Nmap:
		host, err := one(r, true)
		if err != nil {
			return "", nil, PingPlan{}, err
		}
		scan, _ := o.str("scan", "connect", "syn", "udp", "ping")
		if win && scan == "syn" { // necesita Npcap y sus privilegios; la beta de Windows no lo ofrece (ADR 0012, i)
			return "", nil, PingPlan{}, i18n.New("diag.err.syn_windows", nil)
		}
		argv = append(argv, map[string]string{"": "-sT", "connect": "-sT", "syn": "-sS", "udp": "-sU", "ping": "-sn"}[scan])
		if v, ok := o.str("ports"); ok {
			if !portsRe.MatchString(v) {
				return "", nil, PingPlan{}, i18n.New("diag.err.ports", i18n.A("value", v))
			}
			argv = append(argv, "-p", v)
		}
		if v, ok := o.num("timing", 0, 5); ok {
			argv = append(argv, "-T"+v)
		}
		if o.boolean("service_detection") {
			argv = append(argv, "-sV")
		}
		if o.strictBool("skip_discovery") {
			if scan == "ping" { // -sn y -Pn se contradicen: se rechaza en vez de descartar la opción
				o.fail(i18n.New("diag.err.skip_with_ping", nil)) // fail conserva el primer error
			}
			argv = append(argv, "-Pn")
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
				return "", nil, PingPlan{}, i18n.Wrap("diag.err.iperf_client", err, nil)
			}
			argv = []string{"-c", host}
		case "server":
			// Nunca en todas las interfaces: -B con una IP de esta máquina; puerto no privilegiado en Linux.
			b, _ := o.str("bind")
			if a, err := netip.ParseAddr(b); err != nil || !isLocalIP(a) || a.IsLinkLocalUnicast() { // -B sin zona falla con link-local
				return "", nil, PingPlan{}, i18n.New("diag.err.iperf_bind", i18n.A("value", b))
			}
			argv = []string{"-s", "-B", b}
		}
		lo := 1.0
		if mode == "server" && !win { // en Windows no hay puertos privilegiados (ADR 0012 h)
			lo = 1024
		}
		if v, ok := o.num("port", lo, 65535); ok {
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
			return "", nil, PingPlan{}, i18n.New("diag.err.pcap_target", nil)
		}
		if r.OutputDir == "" {
			return "", nil, PingPlan{}, i18n.New("diag.err.pcap_dir", nil)
		}
		iface, ok := o.str("interface")
		re := ifaceRe
		if win {
			re = winIfaceRe
			iface = winIfaceName(iface, winAdapters()) // nombre amistoso -> NPF; el resultado también se valida
		}
		if !ok || !re.MatchString(iface) {
			return "", nil, PingPlan{}, i18n.New("diag.err.pcap_iface", nil)
		}
		argv = []string{"-i", iface}
		v, ok := o.num("seconds", 1, 3600)
		if !ok && win { // cancelar es terminar el job y dejaría el pcapng truncado: siempre hay tope de tiempo
			v, ok = "60", true
		}
		if ok {
			argv = append(argv, "-a", "duration:"+v)
		}
		if v, ok := o.num("packets", 1, 1000000); ok {
			argv = append(argv, "-c", v)
		}
		if v, ok := o.str("filter"); ok && v != "" {
			if strings.ContainsRune(v, 0) {
				return "", nil, PingPlan{}, i18n.New("diag.err.pcap_filter", nil)
			}
			argv = append(argv, "-f", v) // un solo argv: sin shell no hay inyección
		}
		bin = "dumpcap"
	default:
		return "", nil, PingPlan{}, i18n.New("diag.err.tool_unknown", i18n.A("tool", string(r.Tool)))
	}
	if err := o.done(); err != nil {
		return "", nil, PingPlan{}, err
	}
	if err := checkFlagLike(bin, argv, win); err != nil {
		return "", nil, PingPlan{}, err
	}
	return bin, argv, plan, nil
}

// checkFlagLike es la defensa final: ningún valor que venga del usuario puede parecer una bandera (en Windows, tampoco «/x»).
// Lo que sigue a «-f» (el filtro de captura) se exime solo en dumpcap.
func checkFlagLike(bin string, argv []string, win bool) error {
	for i, a := range argv {
		if (strings.HasPrefix(a, "-") && !literalFlags[a] || win && strings.HasPrefix(a, "/")) && !(bin == "dumpcap" && i > 0 && argv[i-1] == "-f") {
			return i18n.New("diag.err.flag_like", i18n.A("value", a))
		}
	}
	return nil
}

// localIPs lista las direcciones de las interfaces de esta máquina; las pruebas la sustituyen.
var localIPs = realLocalIPs

func realLocalIPs() (out []netip.Addr) {
	ifs, _ := ifaces.List()
	for _, i := range ifs {
		for _, a := range i.Addresses {
			if p, err := netip.ParsePrefix(a); err == nil {
				out = append(out, p.Addr())
			}
		}
	}
	return out
}

func isLocalIP(a netip.Addr) bool {
	if a.IsUnspecified() {
		return false
	}
	for _, l := range localIPs() {
		if l == a {
			return true
		}
	}
	return false
}

var literalFlags = map[string]bool{"-B": true, "-n": true, "-c": true, "-i": true, "-s": true, "-m": true, "-sT": true, "-sS": true, "-sU": true, "-sn": true,
	"-p": true, "-T0": true, "-T1": true, "-T2": true, "-T3": true, "-T4": true, "-T5": true, "-sV": true, "-Pn": true, "-6": true, "-oG": true, "-": true,
	"-P": true, "-R": true, "-u": true, "-t": true, "-1": true, "-a": true, "-f": true, "-w": true,
	"-l": true, "-h": true, "-d": true,
	"-I": true, "-M": true, "-W": true, "-Q": true, "-4": true, "-S": true}

// NmapZeroUp dice si la línea final de nmap (-oG) informa 0 hosts up.
func NmapZeroUp(line string) bool {
	return strings.HasPrefix(line, "# Nmap done") && strings.Contains(line, "(0 hosts up)")
}
