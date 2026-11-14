package playbook

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ErrDenied es el centinela de un comando rechazado: errors.Is lo reconoce en cualquier error de denied.
var ErrDenied = i18n.New("playbook.err.denied", nil)

// deniedErr es el error de un comando rechazado: con código del catálogo y errors.Is(ErrDenied).
type deniedErr struct{ e *i18n.Error }

func (d deniedErr) Error() string               { return d.e.Error() }
func (d deniedErr) Reason() string              { return d.e.Reason() }
func (d deniedErr) Metadata() map[string]string { return d.e.Metadata() }
func (d deniedErr) Localize(loc string) string  { return d.e.Localize(loc) }
func (d deniedErr) Unwrap() error               { return d.e }
func (deniedErr) Is(target error) bool          { return target == ErrDenied }

// word es una palabra de IOS con su abreviatura mínima aceptada: IOS ejecuta
// cualquier prefijo único, así que la comparación es por prefijo.
type word struct{ full, min string }

func (w word) matches(s string) bool { return len(s) >= len(w.min) && strings.HasPrefix(w.full, s) }

// Patrol solo lee (spec §8). En vez de enumerar lo peligroso (tclsh, EEM, archive,
// guestshell, crypto key…) se permite solo lo que no cambia nada.
var allowedFirst = []word{
	{"show", "sh"}, {"dir", "di"}, {"more", "mo"}, {"ping", "pi"},
	{"traceroute", "tr"}, {"verify", "veri"},
}

// terminal solo para ajustar la sesión; "terminal shell" y demás quedan fuera.
var allowedTerminal = []word{{"length", "len"}, {"width", "wid"}}

// Primer operador tras "|": solo filtros. redirect, tee y append escriben a flash o a la red.
var allowedPipe = []word{{"include", "i"}, {"exclude", "e"}, {"begin", "b"}, {"section", "s"}, {"count", "c"}}

// Comandos de shell o de escritura de NX-OS que un pipe posterior podría invocar si el host está mal marcado.
var shellTokens = []string{"sed", "awk", "python", "python3", "bash", "run", "source", "tclsh", "vsh", "email", "diff", "less", "xargs", "perl", "sscp", "cut", "tr", "sort", "uniq", "cp", "mv", "rm", "dd", "sh", "ln", "chmod"}

// shellToken: tok es, o abrevia con 2 o más letras, un comando de shell de NX-OS (que acepta abreviaturas).
func shellToken(tok string) bool {
	return len(tok) >= 2 && slices.ContainsFunc(shellTokens, func(t string) bool { return strings.HasPrefix(t, tok) })
}

var pipeSinks = []word{{"redirect", "r"}, {"tee", "t"}, {"append", "a"}}

// Abbrev dice si tok es una abreviatura (prefijo no vacío) de la palabra completa full: IOS ejecuta
// cualquier prefijo único. Lo comparten las listas negras del modo asistido.
func Abbrev(tok, full string) bool { return tok != "" && strings.HasPrefix(full, tok) }

// denied arma el rechazo de cmd; why es el código del motivo (playbook.why.*).
func denied(cmd, why string) error {
	return deniedErr{i18n.Wrap("playbook.err.denied_cmd", i18n.New(why, nil), i18n.A("cmd", strings.TrimSpace(cmd)))}
}

func matchAny(ws []word, s string) bool {
	for _, w := range ws {
		if w.matches(s) {
			return true
		}
	}
	return false
}

// CheckDenied rechaza todo lo que no sea un comando de lectura (spec §8).
// shortcut: reglas IOS/IOS-XE; cada plataforma de la Fase 2 trae las suyas.
func CheckDenied(platform, cmd string) error {
	for _, r := range cmd {
		// Con exec-character-bits 7 el equipo quita el bit alto: Í (C3 8D) llega como C+CR.
		if r < 0x20 || r > 0x7e {
			return denied(cmd, "playbook.why.ascii")
		}
	}
	// NX-OS encadena comandos con «;» («show version ; reload»): se rechaza en todas las plataformas, por si el host
	// de un Nexus está mal marcado y se aplicaran las reglas de IOS.
	if strings.Contains(cmd, ";") {
		return denied(cmd, "playbook.why.chain")
	}
	// «?» en la terminal interactiva pide ayuda: el editor de línea lo quita y conserva el resto, y corre otro comando (ISE y AireOS tienen su propio motivo).
	// «&», «&&», «||» y «<» los interpreta bash en la CLI de los leaf ACI (iBash); ningún show los necesita.
	// En nx-os (los leaf ACI corren como nx-os) además «$» (expansión), «!» (historial), «\» y «'» (otra forma de citar que el
	// análisis de comillas no sigue); en IOS, ASA y AireOS son anclas y patrones legítimos (^…$, ^!) y no pasan por bash.
	if strings.ContainsAny(cmd, "&<") || strings.Contains(cmd, "?") && platform != "ise" && platform != "wlc-aireos" || strings.Contains(cmd, "||") || platform == "nx-os" && strings.ContainsAny(cmd, `$!\'`) {
		return denied(cmd, "playbook.why.shell")
	}
	// «>» y «>>» escriben a flash; «`» y «$(» ejecutan una sustitución. También para IOS, por si el host está mal marcado.
	if strings.Contains(cmd, ">") {
		return denied(cmd, "playbook.why.redirect")
	}
	if strings.Contains(cmd, "`") || strings.Contains(cmd, "$(") {
		return denied(cmd, "playbook.why.subst")
	}
	if platform == "nx-os" {
		return checkNXOS(cmd)
	}
	if platform == "asa" {
		return checkASA(cmd)
	}
	if platform == "wlc-aireos" {
		return checkAireOS(cmd)
	}
	if platform == "ftd" {
		return checkFTD(cmd)
	}
	if platform == "ise" {
		return checkISE(cmd)
	}
	segs := strings.Split(strings.ToLower(cmd), "|")
	fields := strings.Fields(segs[0])
	if len(fields) == 0 {
		if len(segs) > 1 { // «| redirect …» sin comando: no se deja pasar lo que sigue al pipe
			return denied(cmd, "playbook.why.empty_pipe")
		}
		return nil
	}
	switch {
	case matchAny(allowedFirst, fields[0]):
		if (word{"ping", "pi"}).matches(fields[0]) || (word{"traceroute", "tr"}).matches(fields[0]) {
			if !validProbe(fields) {
				return denied(cmd, "playbook.why.probe")
			}
		}
	case (word{"terminal", "ter"}).matches(fields[0]):
		if len(fields) < 2 || !matchAny(allowedTerminal, fields[1]) {
			return denied(cmd, "playbook.why.terminal")
		}
	default:
		return denied(cmd, "playbook.why.not_read")
	}
	// «to-file» es el único destino de escritura que empieza por «to-» en show; IOS acepta cualquier prefijo único,
	// así que «to-» y «to-f…» lo son. Un nombre como «to-core» no es prefijo de to-file y pasa.
	for _, f := range fields[1:] {
		if remotePath(f) {
			return denied(cmd, "playbook.why.remote")
		}
		if isToFile(f) { // «t», «to», «to-»… abrevian to-file: show … to-file flash:x escribe
			return denied(cmd, "playbook.why.to_file")
		}
	}
	for i, seg := range segs[1:] {
		f := strings.Fields(seg)
		if len(f) == 0 {
			if i == 0 {
				return denied(cmd, "playbook.why.empty_pipe")
			}
			continue // parte de una expresión regular
		}
		if matchAny(pipeSinks, f[0]) {
			return denied(cmd, "playbook.why.pipe_sink")
		}
		if i > 0 && shellToken(f[0]) { // plataforma mal marcada: en un Nexus cada «|» es un pipe nuevo
			return denied(cmd, "playbook.why.pipe_shell")
		}
		if i == 0 && !matchAny(allowedPipe, f[0]) {
			return denied(cmd, "playbook.why.pipe_filter")
		}
	}
	return nil
}

// Sistemas de archivos remotos de IOS: more/dir/verify/show file con uno de estos hacen que el equipo se conecte a
// otro servidor (y le mande sus credenciales de ftp/http si las tiene), fuera del EgressGuard.
var remoteFS = []string{"ftp:", "tftp:", "http:", "https:", "scp:", "rcp:", "sftp:"}

func remotePath(f string) bool {
	if strings.Contains(f, "://") {
		return true
	}
	for _, p := range remoteFS {
		if strings.HasPrefix(f, p) {
			return true
		}
	}
	return false
}

// probeOpt es una opción de ping/traceroute: nargs valores numéricos con tope [lo,hi], o un nombre (nargs 0, name).
type probeOpt struct {
	w      word
	lo, hi int
	nargs  int
	name   bool
}

// Lista cerrada. Un paquete de terceros no debe poder pedir repeat/size/timeout absurdos en toda la flota.
var pingOpts = []probeOpt{
	{w: word{"repeat", "rep"}, lo: 1, hi: 10, nargs: 1}, {w: word{"size", "si"}, lo: 1, hi: 1500, nargs: 1},
	{w: word{"timeout", "ti"}, lo: 1, hi: 10, nargs: 1}, {w: word{"source", "so"}, name: true},
}
var traceOpts = []probeOpt{
	{w: word{"ttl", "ttl"}, lo: 1, hi: 30, nargs: 2}, {w: word{"timeout", "ti"}, lo: 1, hi: 10, nargs: 1},
	{w: word{"probe", "pr"}, lo: 1, hi: 5, nargs: 1}, {w: word{"source", "so"}, name: true},
}

// token válido para destino, VRF o fuente: nombre, IPv4/IPv6 o interfaz (sin espacios ni metacaracteres).
func probeName(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || strings.ContainsRune(".:_-/", r)) {
			return false
		}
	}
	return s != ""
}

// probeDest: destino de ping o traceroute en cualquier plataforma. IPv4 solo con 4 octetos decimales sin ceros a la
// izquierda (Go los rechaza) o IPv6 válida, sin las direcciones de difusión, multicast, link-local ni sin especificar;
// si no es una IP, un nombre DNS con letras en la última etiqueta, sin etiquetas «0x» y con un punto final opcional.
// El equipo resuelve «224.1», «4294967295», «0xffffffff» o «127.1» como otra dirección, y un dato «{x}» ya validado
// por su tipo pasa.
func probeDest(s string) bool {
	if isHolder(s) {
		return true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return !badProbeAddr(a)
	}
	labels := strings.Split(strings.TrimSuffix(s, "."), ".")
	if strings.Contains(s, ":") || !strings.ContainsAny(labels[len(labels)-1], "abcdefghijklmnopqrstuvwxyz") {
		return false
	}
	return !slices.ContainsFunc(labels, func(l string) bool { return strings.HasPrefix(l, "0x") })
}

// Palabras de protocolo y sub-modo que IOS completa por prefijo: un destino así abre el diálogo extendido.
var probeKeywords = []string{"ip", "ipv6", "clns", "tag", "atm", "mpls", "appletalk", "decnet", "ipx", "vines", "xns", "apollo", "srb", "ethernet", "mac", "vrf", "oldvines"}

func probeKeyword(s string) bool {
	for _, k := range probeKeywords {
		if strings.HasPrefix(k, s) {
			return true
		}
	}
	return false
}

func probeNum(s string, lo, hi int) (int, bool) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' || len(s) > 4 {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, s != "" && n >= lo && n <= hi
}

// validProbe acepta `ping|traceroute [vrf V] [ip|ipv6] DESTINO [opciones]` con opciones de lista cerrada, sin
// repetir y con topes; todo lo demás (data, df-bit, validate, el diálogo interactivo sin destino…) se rechaza.
func validProbe(f []string) bool {
	opts := pingOpts
	if !(word{"ping", "pi"}).matches(f[0]) {
		opts = traceOpts
	}
	f = f[1:]
	if len(f) >= 2 && (word{"vrf", "vr"}).matches(f[0]) {
		if !probeName(f[1]) {
			return false
		}
		f = f[2:]
	}
	if len(f) > 0 && (f[0] == "ip" || f[0] == "ipv6") {
		f = f[1:]
	}
	if len(f) == 0 || !(isHolder(f[0]) || probeName(f[0]) && probeDest(f[0])) || probeKeyword(f[0]) { // un prefijo de palabra clave abre el diálogo interactivo
		return false
	}
	if a, err := netip.ParseAddr(f[0]); err == nil && badProbeAddr(a) {
		return false // IOS pide «Output Interface» y abre el diálogo
	}
	f = f[1:]
	seen := map[string]bool{}
	for len(f) > 0 {
		var o *probeOpt
		for i := range opts {
			if opts[i].w.matches(f[0]) {
				o = &opts[i]
			}
		}
		if o == nil || seen[o.w.full] {
			return false
		}
		seen[o.w.full] = true
		f = f[1:]
		if o.name {
			if len(f) == 0 || !probeName(f[0]) {
				return false
			}
			f = f[1:]
			continue
		}
		if len(f) < o.nargs {
			return false
		}
		prev := 0
		for i := 0; i < o.nargs; i++ {
			n, ok := probeNum(f[i], o.lo, o.hi)
			if !ok || n < prev { // ttl min max: max no menor que min
				return false
			}
			prev = n
		}
		f = f[o.nargs:]
	}
	return true
}

// badProbeAddr: destinos de ping/traceroute que abren el diálogo o hacen difusión. Una IPv4 mapeada (::ffff:a.b.c.d)
// se juzga como la IPv4 que envuelve.
func badProbeAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// isToFile: «to-file» y sus prefijos («t», «to», «to-»…) son el destino de escritura de show en IOS.
func isToFile(f string) bool { return f != "" && strings.HasPrefix("to-file", f) }

// WritesOnOtherFamily dice si cmd lleva un destino de escritura de la otra familia: «to-file» (IOS/IOS-XE) o
// «file» (ASA) entre los argumentos, antes del pipe. Un script que se manda a la terminal sin saber la plataforma
// de la sesión no debe contar como de lectura si escribe en alguna de las dos.
func WritesOnOtherFamily(cmd string) bool {
	cmdPart, _, _ := strings.Cut(strings.ToLower(cmd), "|")
	f := strings.Fields(cmdPart)
	if len(f) == 0 {
		return false
	}
	for i, a := range f[1:] {
		if isToFile(a) || i > 0 && Abbrev(a, "file") { // «show file systems»: «file» en primer lugar es el subcomando, no un destino
			return true
		}
	}
	return false
}
