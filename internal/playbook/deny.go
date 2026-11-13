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
	case (word{"terminal", "ter"}).matches(fields[0]):
		if len(fields) < 2 || !matchAny(allowedTerminal, fields[1]) {
			return denied(cmd, "playbook.why.terminal")
		}
	default:
		return denied(cmd, "playbook.why.not_read")
	}
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
