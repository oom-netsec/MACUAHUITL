package bridge

import "github.com/oom-netsec/MACUAHUITL/internal/i18n"

// ElevatedText es el aviso de la app de Windows cuando su token está elevado (UAC apagado o el Administrador integrado,
// ADR 0012 (c)): el núcleo se negaría a arrancar y la app solo diría «desconectado». En los dos idiomas, inglés primero,
// porque al arrancar aún no se sabe cuál eligió el usuario. La lógica vive aquí para probarse en Linux.
// AppLogText es el aviso cuando la app de Windows no puede abrir su registro (p. ej. State de otro dueño): sin consola, si
// no se dice aquí no queda en ningún lado. En los dos idiomas, inglés primero.
func AppLogText(path string, err error) string {
	return i18n.Msg(i18n.En, "ui.err.applog", i18n.A("path", path, "err", i18n.In(i18n.En, err))) + "\n\n" +
		i18n.Msg(i18n.Es, "ui.err.applog", i18n.A("path", path, "err", i18n.In(i18n.Es, err)))
}

func ElevatedText() string {
	return i18n.Msg(i18n.En, "ui.err.elevated", nil) + "\n\n" + i18n.Msg(i18n.Es, "ui.err.elevated", nil)
}
