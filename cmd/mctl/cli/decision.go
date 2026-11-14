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

// WireDecision es el valor que viaja por gRPC (histórico, no cambiar sin versionar el cable): el histórico en español (renombrar, reemplazar, omitir). Un mctl nuevo
// con un núcleo anterior (el servicio de usuario sigue corriendo tras actualizar el paquete) lo rechazaría si mandara
// el inglés; el núcleo nuevo acepta los dos. Lo desconocido pasa tal cual.
func WireDecision(canon string) string {
	switch canon {
	case "rename":
		return "renombrar"
	case "replace":
		return "reemplazar"
	case "skip":
		return "omitir"
	}
	return canon
}
