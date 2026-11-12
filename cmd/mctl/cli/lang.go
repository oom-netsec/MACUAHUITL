package cli

import (
	"fmt"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// validLang acepta es, en o una etiqueta con guion (es-MX, en-US).
func validLang(v string) bool {
	v = strings.ToLower(v)
	return v == "es" || v == "en" || (strings.Contains(v, "-") && !strings.HasPrefix(v, "-") && !strings.HasSuffix(v, "-"))
}

// StripLang quita la bandera global --lang X, --lang=X, -lang X o -lang=X, que solo vale ANTES del subcomando (se
// detiene en el primer argumento que no es bandera y en «--»). Nunca se come el nombre del comando: el valor debe ser
// es, en o una etiqueta con guion; otro valor es un error («mctl --lang vault status» no se come «vault»).
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
