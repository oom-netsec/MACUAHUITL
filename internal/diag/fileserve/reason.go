package fileserve

import (
	"errors"
	"strings"
	"sync"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

const reasonCodes = "fileserve.reason."

var (
	litOnce sync.Once
	litByEs map[string]string // texto en español de un motivo sin argumentos -> su código del catálogo
)

// lit da el Text del motivo fijo cuyo texto en español es es (búsqueda en un mapa, sin recursión); vacío si no es
// un motivo del catálogo (un error del sistema, «HTTP 404»).
func lit(es string) i18n.Text {
	litOnce.Do(func() {
		litByEs = map[string]string{}
		for _, c := range i18n.Codes() {
			if t := i18n.Msg(i18n.Es, c, nil); strings.HasPrefix(c, reasonCodes) && !strings.Contains(t, "{") {
				litByEs[t] = c
			}
		}
	})
	if c, ok := litByEs[es]; ok {
		return i18n.Tx(c)
	}
	return i18n.Text{}
}

// why arma el Text del motivo con argumentos fileserve.reason.<key>.
func why(key string, kv ...any) i18n.Text { return i18n.Tx(reasonCodes+key, kv...) }

// setErr pone err como motivo: con código del catálogo se conserva; si no, se busca su texto fijo.
func (t *Transfer) setErr(err error) {
	t.Error = err.Error()
	var ie *i18n.Error
	if errors.As(err, &ie) {
		t.ReasonT = i18n.Text{Key: ie.Code, Args: ie.Args}
		return
	}
	t.ReasonT = lit(t.Error)
}

// ReasonIn da el motivo de t en el idioma loc. Sin Text de catálogo (un error del sistema, «HTTP 404») es el texto de
// siempre; con es, también.
func ReasonIn(loc string, t Transfer) string {
	if loc != i18n.En || t.ReasonT.Empty() {
		return t.Error
	}
	return t.ReasonT.In(loc)
}
