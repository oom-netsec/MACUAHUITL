package diag

import (
	"net/netip"
	"runtime"
	"strconv"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ifaces"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// PingPlan es lo que Build valida de ping pero no vuelve bandera: lo aplica el núcleo (200-3 continuo y duración, 200-4 barrido).
// Con barrido (200-4) el argv de Build va sin -s/-l: el núcleo inserta el tamaño antes del host, y ese argv aumentado
// tiene que volver a pasar por checkFlagLike.
type PingPlan struct {
	Continuous bool
	Duration   int    // segundos en total; 0 = sin tope propio
	Count      int    // por ejecución (con barrido, por tamaño)
	Sweep      *Sweep // nil si no hay barrido
}

// Sweep es el barrido de tamaños ya validado: Start, Start+Step, ... hasta End (máximo 100).
type Sweep struct{ Start, End, Step int }

func (s Sweep) Sizes() (out []int) {
	for v := s.Start; v <= s.End; v += s.Step {
		out = append(out, v)
	}
	return out
}

// Plan devuelve el plan de un ping, con las mismas validaciones que Build para el sistema actual.
func Plan(r Request) (PingPlan, error) {
	if r.Tool != Ping {
		return PingPlan{}, i18n.New("diag.err.not_ping", nil)
	}
	_, _, p, err := buildPlan(r, runtime.GOOS == "windows")
	return p, err
}

// localIfaceNames lista los nombres de interfaz de esta máquina; las pruebas la sustituyen.
var localIfaceNames = realIfaceNames

func realIfaceNames() (out []string) {
	ifs, _ := ifaces.List()
	for _, i := range ifs {
		out = append(out, i.Name)
	}
	return out
}

// norm quita ceros a la izquierda para que «007» no llegue a ping como posible octal.
func norm(s string) string { return strconv.Itoa(atoi(s)) }

func atoi(s string) int { n, _ := strconv.Atoi(s); return n } // solo tras o.num: ya son dígitos

func pingArgs(o *opts, host string, win bool) (p PingPlan, argv []string) {
	winOnly := func(key string) {
		o.used[key] = true
		o.fail(i18n.New("diag.err.opt_windows", i18n.A("key", key)))
	}
	hostAddr, _ := netip.ParseAddr(host)

	// barrido: los tres o ninguno
	ss, ok1 := o.num("sweep_start", 0, 65500)
	se, ok2 := o.num("sweep_end", 0, 65500)
	st, ok3 := o.num("sweep_step", 1, 65500)
	_, h1 := o.m["sweep_start"]
	_, h2 := o.m["sweep_end"]
	_, h3 := o.m["sweep_step"]
	if (h1 || h2 || h3) && !(ok1 && ok2 && ok3) {
		if o.err == nil {
			o.fail(i18n.New("diag.err.sweep_all", nil))
		}
	} else if ok1 {
		sw := Sweep{atoi(ss), atoi(se), atoi(st)}
		switch {
		case sw.End < sw.Start:
			o.fail(i18n.New("diag.err.number", i18n.A("key", "sweep_end", "lo", ss, "hi", "65500")))
		case (sw.End-sw.Start)/sw.Step+1 > 100:
			o.fail(i18n.New("diag.err.sweep_max", nil))
		}
		p.Sweep = &sw
	}

	countHi := 100.0
	if p.Sweep != nil {
		countHi = 5
	}
	count, ok := o.num("count", 1, countHi)
	if !ok {
		count = "4"
		if p.Sweep != nil {
			count = "1"
		}
	}
	count = norm(count)
	p.Count = atoi(count)
	p.Continuous = o.boolean("continuous")
	if d, ok := o.num("duration", 1, 3600); ok {
		p.Duration = atoi(d)
	}
	size, hasSize := o.num("size", 0, 65500)
	size = norm(size)
	if p.Sweep != nil && p.Continuous {
		o.fail(i18n.New("diag.err.combo", i18n.A("a", "continuous", "b", "sweep", "key", "continuous")))
	}
	if p.Sweep != nil && hasSize {
		o.fail(i18n.New("diag.err.combo", i18n.A("a", "size", "b", "sweep", "key", "size")))
	}

	family, _ := o.str("family", "4", "6")
	if hostAddr.IsValid() && family != "" && family != map[bool]string{false: "4", true: "6"}[hostAddr.Is6()] {
		o.fail(i18n.New("diag.err.combo", i18n.A("a", "family", "b", "target", "key", "family")))
	}
	ttl, hasTTL := o.num("ttl", 1, 255)
	timeout, hasTimeout := o.num("timeout", 1, 60)
	ttl, timeout = norm(ttl), norm(timeout)
	df := o.boolean("df")

	var src string
	var srcAddr netip.Addr
	if v, ok := o.m["source"]; ok {
		o.used["source"] = true
		a, err := netip.ParseAddr(v)
		switch {
		case err == nil && a.Zone() == "" && !a.Is4In6() && !a.IsLinkLocalUnicast() && isLocalIP(a):
			src, srcAddr = v, a
		case err != nil && ifaceRe.MatchString(v) && hasName(v):
			if win {
				winOnly("source")
			}
			src = v
		default:
			o.fail(i18n.New("diag.err.source_bad", i18n.A("value", v)))
		}
		if srcAddr.IsValid() {
			fam := map[bool]string{false: "4", true: "6"}[srcAddr.Is6()]
			if (family != "" && family != fam) || (hostAddr.IsValid() && hostAddr.Is6() != srcAddr.Is6()) {
				o.fail(i18n.New("diag.err.source_family", i18n.A("value", v)))
			}
		}
	}
	tos, hasTos := o.num("tos", 0, 255)
	tos = norm(tos)

	if win { // Windows: -n cuenta (o -t), -l tamaño, -S origen, -f DF, -i TTL, -w espera en ms; sin intervalo ni ToS
		if _, ok := o.m["interval"]; ok {
			winOnly("interval")
		}
		if _, ok := o.m["tos"]; ok {
			winOnly("tos")
		}
		if df && (family == "6" || hostAddr.IsValid() && hostAddr.Is6() || srcAddr.IsValid() && srcAddr.Is6()) {
			winOnly("df")
		}
		argv = []string{"-n", count}
		if p.Continuous {
			argv = []string{"-t"}
		}
		if hasSize {
			argv = append(argv, "-l", size)
		}
		if srcAddr.IsValid() {
			argv = append(argv, "-S", src)
		}
		if df {
			argv = append(argv, "-f")
		}
		if hasTTL {
			argv = append(argv, "-i", ttl)
		}
		if family != "" {
			argv = append(argv, "-"+family)
		}
		wait := winWaitMs
		if hasTimeout {
			wait = timeout + "000"
		}
		return p, append(argv, "-w", wait, host)
	}
	argv = []string{"-n"}
	if !p.Continuous {
		argv = append(argv, "-c", count)
	}
	if v, ok := o.num("interval", 0.2, 60); ok {
		argv = append(argv, "-i", v)
	}
	if hasSize {
		argv = append(argv, "-s", size)
	}
	if src != "" {
		argv = append(argv, "-I", src)
	}
	if df {
		argv = append(argv, "-M", "do")
	}
	if hasTTL {
		argv = append(argv, "-t", ttl)
	}
	if hasTimeout {
		argv = append(argv, "-W", timeout)
	}
	if hasTos {
		argv = append(argv, "-Q", tos)
	}
	if family != "" {
		argv = append(argv, "-"+family)
	}
	return p, append(argv, host)
}

func hasName(n string) bool {
	for _, l := range localIfaceNames() {
		if l == n {
			return true
		}
	}
	return false
}
