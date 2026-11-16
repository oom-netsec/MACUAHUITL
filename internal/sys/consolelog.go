package sys

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// LogMax es el tamaño del registro del núcleo a partir del cual se rota al arrancar (ADR 0012 g): se renombra a «.1»,
// reemplazando al anterior, así que se conserva uno.
const LogMax = 10 << 20

// OpenLog abre el registro path para agregar al final. Si ya pesa más de max se renombra antes a path+".1"; la rotación
// es de mejor esfuerzo: si el renombrado falla (el registro abierto en un visor, el .1 bloqueado) se sigue agregando al
// final, porque un registro grande es mejor que un núcleo que no arranca sin dejar mensaje. Si no existe nace privado
// (OpenNewPrivate); si existe y no es un archivo regular (un enlace puesto ahí) se rechaza en vez de seguirlo.
// shortcut: se rota solo al abrir; un núcleo que corra semanas puede pasar el tope hasta el siguiente arranque. Entre el
// Lstat y la apertura hay una ventana, pero la carpeta es privada del usuario.
func OpenLog(path string, max int64) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil {
		if !fi.Mode().IsRegular() {
			return nil, i18n.Wrap("sys.err.log_not_regular", fs.ErrInvalid, i18n.A("path", path))
		}
		if fi.Size() > max {
			os.Rename(path, path+".1")
		}
	}
	f, err := OpenNewPrivate(path)
	if err == nil {
		// Nació con la DACL privada pero con su propio puntero: otro proceso que agregue al mismo registro nuevo (la app
		// puede tener dos) sería pisado. Se reabre en modo agregar; la DACL ya quedó puesta al crearlo.
		f.Close()
	} else if !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() { // lo que no sea un archivo regular se rechaza también aquí
		f.Close()
		return nil, i18n.Wrap("sys.err.log_not_regular", fs.ErrInvalid, i18n.A("path", path))
	}
	return f, nil
}

// appendLog agrega una línea fechada al registro sin rotarlo (mejor esfuerzo: el llamador ignora el error).
func appendLog(path, line string) error {
	f, err := OpenLog(path, math.MaxInt64)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), line)
	return err
}
