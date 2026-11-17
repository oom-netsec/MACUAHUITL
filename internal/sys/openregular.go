package sys

import (
	"errors"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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

// ErrWaitTimeout: WaitExit venció el plazo con el proceso aún vivo.
var ErrWaitTimeout = i18n.New("sys.err.wait_timeout", nil)

// OpenOutDir crea (0700) y abre una carpeta de salidas UNA vez (os.Root): lo que se cree después va por ese handle, así que
// cambiar la carpeta por un enlace simbólico o una junction tras abrirla no desvía la escritura. Resuelve los enlaces de la
// ruta (la carpeta de fábrica puede ser un enlace del usuario) y valida lo ABIERTO, no la ruta: el dueño es el usuario y nadie
// más escribe en ella (ForeignWritersRoot: la misma regla de fileserve). Así un enlace cambiado entre la validación de ajustes y
// el uso se rechaza si apunta a una carpeta ajena o compartida; si el destino es propio y privado se acepta. Un volumen sin permisos
// por usuario (FAT, exFAT) se acepta: no hay nada que validar. Quien la llama cierra el Root.
func OpenOutDir(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(real)
	if err != nil {
		return nil, err
	}
	w, err := ForeignWritersRoot(root)
	if err != nil && !errors.Is(err, errors.ErrUnsupported) {
		root.Close()
		return nil, err
	}
	if len(w.Who) > 0 {
		root.Close()
		return nil, i18n.New("sys.err.outdir_shared", i18n.A("dir", real, "who", strings.Join(w.Who, ", ")))
	}
	return root, nil
}

// MkdirOpenIn crea la subcarpeta name (0700) dentro de root si falta y la abre como Root; un enlace en su lugar que salga de
// root se rechaza (os.Root no lo sigue).
func MkdirOpenIn(root *os.Root, name string) (*os.Root, error) {
	if err := root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	return root.OpenRoot(name)
}

// CreateTempIn es os.CreateTemp dentro de una carpeta ya abierta: nombre único (pattern con «*»), archivo nuevo y privado
// (OpenNewPrivateIn: O_EXCL, sin seguir enlaces; en Windows nace con la DACL protegida).
func CreateTempIn(root *os.Root, pattern string) (*os.File, error) {
	pre, suf, _ := strings.Cut(pattern, "*")
	for i := 0; i < 10000; i++ {
		f, err := OpenNewPrivateIn(root, pre+strconv.FormatUint(uint64(rand.Uint32()), 10)+suf)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err
	}
	return nil, &fs.PathError{Op: "createtemp", Path: pattern, Err: fs.ErrExist}
}
