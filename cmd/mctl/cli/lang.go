package cli

import (
	"fmt"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// validLang acepta es, en o una etiqueta cuyo idioma principal sea es o en (es-MX, en-US).
func validLang(v string) bool {
	primary, _, _ := strings.Cut(strings.ToLower(v), "-")
	return primary == "es" || primary == "en"
}

// StripLang quita la bandera global --lang X, --lang=X, -lang X o -lang=X, que solo vale ANTES del subcomando (se
// detiene en el primer argumento que no es bandera y en «--»). Nunca se come el nombre del comando: el valor debe ser
// es, en o una etiqueta cuyo idioma principal sea es o en (es-MX, en-US); otro valor es un error («mctl --lang vault status» no se come «vault»).
// Devuelve el idioma normalizado (es o en), o "" si no se pidió.
func StripLang(args []string) (rest []string, lang string, err error) {
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" || !strings.HasPrefix(a, "-") {
			break
		}
		name, val, hasVal := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		if name != "lang" {
			rest = append(rest, a)
			continue
		}
		if !hasVal {
			if i+1 >= len(args) {
				return nil, "", fmt.Errorf("--lang pide un idioma (es o en)")
			}
			i++
			val = args[i]
		}
		if !validLang(val) {
			return nil, "", fmt.Errorf("idioma inválido %q (usa es o en)", val)
		}
		lang = i18n.Parse(val)
	}
	return append(rest, args[i:]...), lang, nil
}

// locale es el idioma de los mensajes propios de mctl (los del núcleo ya llegan en él por accept-language): en salvo
// que main reciba --lang es. Se fija una vez, antes de despachar el comando.  La ayuda y los «uso: mctl …» siguen el mismo idioma.
var locale = i18n.En

// SetLang fija el idioma de los mensajes propios de mctl (el que devuelve StripLang; "" = en).
func SetLang(lang string) { locale = i18n.Normalize(lang) }

// Lang es el idioma vigente de los mensajes propios de mctl (es o en).
func Lang() string { return locale }

// T es el texto del código del catálogo en el idioma de mctl; los pares son nombre, valor (como i18n.A).
func T(code string, kv ...any) string { return i18n.Msg(locale, code, i18n.A(kv...)) }

// coded es un error con código del catálogo que se escribe en el idioma de mctl (con es, el texto de siempre).
type coded struct{ e *i18n.Error }

func (c coded) Error() string { return c.e.Localize(locale) }
func (c coded) Unwrap() error { return c.e }

// Err es un error con el texto del código en el idioma de mctl.
func Err(code string, kv ...any) error { return coded{i18n.New(code, i18n.A(kv...))} }

// ErrWrap es Err con una causa: la plantilla la usa como {cause} y errors.Is/As la alcanzan.
func ErrWrap(code string, cause error, kv ...any) error {
	return coded{i18n.Wrap(code, cause, i18n.A(kv...))}
}
