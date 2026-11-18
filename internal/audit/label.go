package audit

import "github.com/oom-netsec/MACUAHUITL/internal/i18n"

// ActionLabel es el texto con que se muestra una acción en el idioma pedido. La clave guardada en la cadena de hashes
// (hosts.crear…) no cambia nunca: solo se traduce lo que se ve. Una acción sin etiqueta se muestra tal cual.
func ActionLabel(loc, action string) string {
	key := "audit.action." + action
	if l := i18n.Msg(loc, key, nil); l != key {
		return l
	}
	return action
}
