package fileserve

import (
	"regexp"
	"strings"
	"sync"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

var (
	reasonOnce  sync.Once
	reasonByEs  map[string]string // texto en español de un motivo sin argumentos → su código del catálogo
	optionRe    = regexp.MustCompile(`^opción -(.) no permitida$`)
	reasonCodes = "fileserve.reason."
)

// ReasonIn da en el idioma loc el motivo de rechazo o de falla que un servidor puso en Transfer.Error. Los motivos son
// textos en español del catálogo (fileserve.reason.*); lo que no es uno de ellos (un error del sistema, «HTTP 404»)
// se queda como está. Con es, o sin motivo, es el mismo texto.
func ReasonIn(loc, es string) string {
	if loc != i18n.En || es == "" {
		return es
	}
	reasonOnce.Do(func() {
		reasonByEs = map[string]string{}
		for _, c := range i18n.Codes() {
			if t := i18n.Msg(i18n.Es, c, nil); strings.HasPrefix(c, reasonCodes) && !strings.Contains(t, "{") {
				reasonByEs[t] = c
			}
		}
	})
	if c, ok := reasonByEs[es]; ok {
		return i18n.Msg(loc, c, nil)
	}
	for _, p := range []struct{ prefix, code, arg string }{
		{"método ", "method", "method"}, {"interrumpida: ", "interrupted", "error"}, {"exec rechazado: ", "exec_rejected", "reason"},
	} {
		if rest, ok := strings.CutPrefix(es, p.prefix); ok {
			if p.arg == "reason" {
				rest = ReasonIn(loc, rest)
			}
			return i18n.Msg(loc, reasonCodes+p.code, i18n.A(p.arg, rest))
		}
	}
	if m := optionRe.FindStringSubmatch(es); m != nil {
		return i18n.Msg(loc, reasonCodes+"option_not_allowed", i18n.A("opt", m[1]))
	}
	return es
}
