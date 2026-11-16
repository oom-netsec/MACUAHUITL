package bridge

import "github.com/oom-netsec/MACUAHUITL/internal/i18n"

// ElevatedText es el aviso de la app de Windows cuando su token está elevado (UAC apagado o el Administrador integrado,
// ADR 0012 (c)): el núcleo se negaría a arrancar y la app solo diría «desconectado». En los dos idiomas, inglés primero,
// porque al arrancar aún no se sabe cuál eligió el usuario. La lógica vive aquí para probarse en Linux.
func ElevatedText() string {
	return "MACUAHUITL " + i18n.Msg(i18n.En, "harden.err.elevated", nil) + "\n\nMACUAHUITL " + i18n.Msg(i18n.Es, "harden.err.elevated", nil)
}
