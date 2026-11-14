package bridge

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ---- Guardar un archivo que eligió la persona ----

const maxSaveBytes = 64 << 20

// ErrFileExists: la ruta ya existe y no se pidió sobrescribir. El frontend pregunta y reintenta con overwrite.
var ErrFileExists = errors.New("save: the file already exists")

// WriteFile escribe data en path, la ruta que la persona eligió en el diálogo nativo de guardar (lo abre el
// frontend con el runtime de Wails). El diálogo GTK3 de Wails no confirma la sobrescritura, así que aquí no se
// reemplaza nada sin overwrite. Se escribe a un temporal en la misma carpeta y se renombra: un fallo a medias
// (disco lleno) no destruye el archivo anterior. Lo usan las exportaciones: CSV, PNG, .cfg, .txt y Markdown.
func (b *Bridge) WriteFile(path, data, encoding string, overwrite bool) error {
	if !filepath.IsAbs(path) {
		return b.bridgeErr(i18n.New("bridge.err.save_abs", nil))
	}
	var raw []byte
	switch encoding {
	case "utf8":
		raw = []byte(data)
	case "base64":
		var err error
		if raw, err = base64.StdEncoding.DecodeString(data); err != nil {
			return b.bridgeErr(i18n.Wrap("bridge.err.save_base64", err, nil))
		}
	default:
		return b.bridgeErr(i18n.New("bridge.err.save_encoding", i18n.A("encoding", encoding)))
	}
	if len(raw) > maxSaveBytes {
		return b.bridgeErr(i18n.New("bridge.err.save_big", nil))
	}
	if _, err := os.Lstat(path); err == nil && !overwrite {
		return &Error{err: ErrFileExists, msg: i18n.Msg(b.locale(), "file.exists.save", nil), Code: "AlreadyExists", Reason: "file.exists",
			Metadata: i18n.Metadata("file.exists.save", i18n.A("path", path))}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guardar-*")
	if err != nil {
		return wrapErr(err)
	}
	defer os.Remove(tmp.Name()) // tras el rename ya no existe
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return wrapErr(err)
	}
	if err := tmp.Close(); err != nil {
		return wrapErr(err)
	}
	return wrapErr(os.Rename(tmp.Name(), path)) // CreateTemp ya deja 0600
}
