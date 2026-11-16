package sys

import (
	"os"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ErrNotRegular: la ruta existe pero no es un archivo regular (FIFO, dispositivo, directorio).
var ErrNotRegular = i18n.New("sys.err.not_regular", nil)

// OpenRegular abre path solo para lectura sin quedarse bloqueado en una FIFO sin escritor
// (O_NONBLOCK en Linux; en Windows no hay FIFO) y rechaza lo que no sea un archivo regular.
// Úsalo con toda ruta que venga de fuera.
func OpenRegular(path string) (*os.File, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	return regularOnly(f)
}

// OpenRegularIn es OpenRegular dentro de una carpeta ya abierta (os.Root).
func OpenRegularIn(root *os.Root, name string) (*os.File, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|nonBlock, 0)
	if err != nil {
		return nil, err
	}
	return regularOnly(f)
}

func regularOnly(f *os.File) (*os.File, error) {
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, ErrNotRegular
	}
	return f, nil
}

// OpenNew crea un archivo nuevo para leer y escribir (0600). Falla si la ruta ya existe y
// nunca sigue un enlace simbólico en el último componente: no pisa nada que ya esté ahí.
func OpenNew(path string) (*os.File, error) {
	if err := checkPath(path); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|ONoFollow, 0o600)
}

// OpenNewIn es OpenNew dentro de una carpeta ya abierta (os.Root): name no puede salir de ella
// ni seguir un enlace, así cambiar la carpeta por un enlace simbólico después de validarla no desvía la escritura.
func OpenNewIn(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|ONoFollow, 0o600)
}
