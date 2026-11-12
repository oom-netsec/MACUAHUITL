package playbook

import (
	"errors"
	"fmt"
	"strings"
)

var ErrDenied = errors.New("playbook: comando no permitido en una recolección (solo lectura)")

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

func denied(cmd, why string) error {
	return fmt.Errorf("%w: %q (%s)", ErrDenied, strings.TrimSpace(cmd), why)
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
			return denied(cmd, "solo ASCII imprimible; un retorno de carro o un carácter de 8 bits ejecutaría otro comando")
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
			return denied(cmd, "solo terminal length y terminal width")
		}
	default:
		return denied(cmd, "no es un comando de lectura")
	}
	for i, seg := range segs[1:] {
		f := strings.Fields(seg)
		if len(f) == 0 {
			if i == 0 {
				return denied(cmd, "pipe vacío")
			}
			continue // parte de una expresión regular
		}
		if matchAny(pipeSinks, f[0]) {
			return denied(cmd, "redirect, tee y append escriben fuera de la sesión")
		}
		if i == 0 && !matchAny(allowedPipe, f[0]) {
			return denied(cmd, "solo include, exclude, begin, section y count tras |")
		}
	}
	return nil
}
