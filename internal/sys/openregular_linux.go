package sys

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// nonBlock evita colgarse al abrir una FIFO sin escritor.
const nonBlock = syscall.O_NONBLOCK

// Mkfifo crea una FIFO; existe para las pruebas de los paquetes que no pueden importar syscall (noegress).
func Mkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }

// HardLinked dice si el archivo tiene más de un nombre (Nlink > 1): puede ser el mismo inodo
// que otro fuera de la carpeta publicada, así que no se publica. Úsalo como filtro de listado; lo que decide con un
// archivo ya abierto es HardLinkedFile (en Windows un FileInfo no trae la cuenta de enlaces).
func HardLinked(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Nlink > 1
}

// HardLinkedFile es HardLinked sobre un archivo ya abierto: la decisión que cuenta, porque mira el mismo objeto que se
// va a servir. Si no se puede saber, devuelve el error y quien llama rechaza.
func HardLinkedFile(f *os.File) (bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	return HardLinked(fi), nil
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

// RenameNoReplaceIn renombra old a new dentro de root sin sobrescribir (renameat2 con RENAME_NOREPLACE); falla con
// fs.ErrExist si new existe.
func RenameNoReplaceIn(root *os.Root, old, new string) error {
	d, err := root.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	return unix.Renameat2(int(d.Fd()), old, int(d.Fd()), new, unix.RENAME_NOREPLACE)
}

// ErrNoAtomicRename es el error que da un sistema de archivos sin RENAME_NOREPLACE (para simularlo en pruebas).
var ErrNoAtomicRename error = unix.EINVAL

// NoAtomicRename dice si err es que el sistema de archivos no sabe renombrar sin sobrescribir.
func NoAtomicRename(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.EPERM)
}
