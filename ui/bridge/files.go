package bridge

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ---- Guardar un archivo que eligió la persona ----

const maxSaveBytes = 64 << 20

// ErrFileExists: la ruta ya existe y no se pidió sobrescribir. El frontend pregunta y reintenta con overwrite.
var ErrFileExists = errors.New("guardar: el archivo ya existe")

// WriteFile escribe data en path, la ruta que la persona eligió en el diálogo nativo de guardar (lo abre el
// frontend con el runtime de Wails). El diálogo GTK3 de Wails no confirma la sobrescritura, así que aquí no se
// reemplaza nada sin overwrite. Se escribe a un temporal en la misma carpeta y se renombra: un fallo a medias
// (disco lleno) no destruye el archivo anterior. Lo usan las exportaciones: CSV, PNG, .cfg, .txt y Markdown.
func (b *Bridge) WriteFile(path, data, encoding string, overwrite bool) error {
	if !filepath.IsAbs(path) {
		return errors.New("guardar: la ruta debe ser absoluta")
	}
	var raw []byte
	switch encoding {
	case "utf8":
		raw = []byte(data)
	case "base64":
		var err error
		if raw, err = base64.StdEncoding.DecodeString(data); err != nil {
			return fmt.Errorf("guardar: base64 inválido: %w", err)
		}
	default:
		return fmt.Errorf("guardar: codificación %q desconocida", encoding)
	}
	if len(raw) > maxSaveBytes {
		return errors.New("guardar: el archivo pasa de 64 MiB")
	}
	if _, err := os.Lstat(path); err == nil && !overwrite {
		return ErrFileExists
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".guardar-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // tras el rename ya no existe
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path) // CreateTemp ya deja 0600
}
