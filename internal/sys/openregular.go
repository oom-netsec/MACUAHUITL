package sys

import (
	"os"
	"syscall"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ErrNotRegular: la ruta existe pero no es un archivo regular (FIFO, dispositivo, directorio).
var ErrNotRegular = i18n.New("sys.err.not_regular", nil)

// OpenRegular abre path solo para lectura sin quedarse bloqueado en una FIFO sin escritor
// (O_NONBLOCK) y rechaza lo que no sea un archivo regular. Úsalo con toda ruta que venga de fuera.
func OpenRegular(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
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

// Mkfifo crea una FIFO; existe para las pruebas de los paquetes que no pueden importar syscall (noegress).
func Mkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }

// OpenNew crea un archivo nuevo para leer y escribir (0600). Falla si la ruta ya existe y
// nunca sigue un enlace simbólico en el último componente: no pisa nada que ya esté ahí.
func OpenNew(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}

// OpenNewIn es OpenNew dentro de una carpeta ya abierta (os.Root): name no puede salir de ella
// ni seguir un enlace, así cambiar la carpeta por un enlace simbólico después de validarla no desvía la escritura.
func OpenNewIn(root *os.Root, name string) (*os.File, error) {
	return root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}

// OpenRegularIn es OpenRegular dentro de una carpeta ya abierta (os.Root).
func OpenRegularIn(root *os.Root, name string) (*os.File, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
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

// HardLinked dice si el archivo tiene más de un nombre (Nlink > 1): puede ser el mismo inodo
// que otro fuera de la carpeta publicada, así que no se publica.
func HardLinked(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink > 1
}

// Owner devuelve el uid dueño del archivo; ok es false si el sistema no lo informa.
func Owner(fi os.FileInfo) (uid uint32, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// ONoFollow es el indicador O_NOFOLLOW de open(2): falla si el último componente es un enlace simbólico.
const ONoFollow = syscall.O_NOFOLLOW
