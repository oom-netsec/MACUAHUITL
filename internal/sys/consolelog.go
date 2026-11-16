package sys

import (
	"errors"
	"io/fs"
	"os"
)

// LogMax es el tamaño del registro del núcleo a partir del cual se rota al arrancar (ADR 0012 g): se renombra a «.1»,
// reemplazando al anterior, así que se conserva uno.
const LogMax = 10 << 20

// OpenLog abre el registro path para agregar al final. Si ya pesa más de max se renombra antes a path+".1". Si no existe
// nace privado (OpenNewPrivate); si existe se abre tal cual, porque ya nació así y vive en una carpeta privada.
// shortcut: se rota solo al abrir; un núcleo que corra semanas puede pasar el tope hasta el siguiente arranque.
func OpenLog(path string, max int64) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() && fi.Size() > max {
		if err := os.Rename(path, path+".1"); err != nil {
			return nil, err
		}
	}
	f, err := OpenNewPrivate(path)
	if errors.Is(err, fs.ErrExist) {
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	}
	return f, err
}
