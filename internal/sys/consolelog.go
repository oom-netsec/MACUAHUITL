package sys

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"time"
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
			return nil, fmt.Errorf("%s: %w (no es un archivo regular)", path, fs.ErrInvalid)
		}
		if fi.Size() > max {
			os.Rename(path, path+".1")
		}
	}
	f, err := OpenNewPrivate(path)
	if errors.Is(err, fs.ErrExist) {
		f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	}
	return f, err
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
