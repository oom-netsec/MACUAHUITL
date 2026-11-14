package cli

import (
	"slices"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Decision lleva el valor de --decision o --all a su forma canónica en inglés (rename, replace, skip; los alias
// renombrar, reemplazar y omitir siguen valiendo) y dice si está entre los permitidos (por omisión, los tres).
func Decision(v string, allowed ...string) (string, bool) {
	v = i18n.Decision(v)
	if len(allowed) == 0 {
		allowed = []string{"rename", "replace", "skip"}
	}
	return v, slices.Contains(allowed, v)
}
