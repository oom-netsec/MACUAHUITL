package playbook

import (
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
	segs := strings.Split(strings.ToLower(cmd), "|")
	fields := strings.Fields(segs[0])
	if len(fields) == 0 {
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
	for _, f := range fields {
		if len(f) >= 3 && strings.HasPrefix(f, "to-") && strings.HasPrefix("to-file", f) { // show … to-file flash:x escribe
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
		if i == 0 && !matchAny(allowedPipe, f[0]) {
			return denied(cmd, "playbook.why.pipe_filter")
		}
	}
	return nil
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
	{w: word{"ttl", "ttl"}, lo: 1, hi: 255, nargs: 2}, {w: word{"timeout", "ti"}, lo: 1, hi: 10, nargs: 1},
	{w: word{"probe", "pr"}, lo: 1, hi: 10, nargs: 1}, {w: word{"source", "so"}, name: true},
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
	if len(f) == 0 || !probeName(f[0]) || (word{"vrf", "vr"}).matches(f[0]) { // «ping vrf» sin nombre no es un destino
		return false
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
