package cli

import (
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// StripValueFlag quita --nombre valor y --nombre=valor de args y devuelve el último valor. Sin valor (la bandera al final) da "".
func StripValueFlag(args []string, name string) (rest []string, value string, found bool) {
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == name:
			found, value = true, ""
			if i+1 < len(args) {
				value = args[i+1]
				i++
			}
		case strings.HasPrefix(a, name+"="):
			found, value = true, strings.TrimPrefix(a, name+"=")
		default:
			rest = append(rest, a)
		}
	}
	return rest, value, found
}

// Lang es el idioma que mctl pide al núcleo (es o en): la bandera --lang; si no, LC_ALL, LC_MESSAGES y LANG por ese orden
// (lo primero que no esté vacío); si no, es. «C» y «POSIX» y lo desconocido valen es. Los textos propios de mctl no se traducen.
func Lang(flag string, getenv func(string) string) string {
	v := flag
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v == "" {
			v = getenv(k)
		}
	}
	return i18n.Parse(v)
}
