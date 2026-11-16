package sys

import (
	"os"
	"path/filepath"
)

// MkdirPrivate crea la carpeta y sus padres con 0700 (ADR 0012, c); la ruta debe ser absoluta. En Windows la deja con
// una DACL protegida.
func MkdirPrivate(path string) error {
	if err := requireAbs(path); err != nil {
		return err
	}
	return os.MkdirAll(path, 0o700)
}

// OpenNewPrivate es OpenNew: el archivo nace 0600 (O_EXCL|O_NOFOLLOW). En Windows nace con la DACL protegida.
func OpenNewPrivate(path string) (*os.File, error) { return OpenNew(path) }

// OpenNewPrivateIn es OpenNewIn: nace 0600, dentro de una carpeta ya abierta.
func OpenNewPrivateIn(root *os.Root, name string) (*os.File, error) { return OpenNewIn(root, name) }

// CreateTempPrivate es os.CreateTemp, que ya crea 0600.
func CreateTempPrivate(dir, pattern string) (*os.File, error) { return os.CreateTemp(dir, pattern) }

// ProtectFile deja el archivo en 0600. Para uno que ya existe; hoy ninguna ruta de producción la necesita (los archivos
// nuevos nacen privados con OpenNewPrivate), queda para eso y para las pruebas.
func ProtectFile(path string) error { return os.Chmod(path, 0o600) }

// ProtectNewStrict protege un archivo recién creado con O_CREATE y 0600 (que en Linux ya nació privado): no hace nada.
func ProtectNewStrict(string) error { return nil }

// OnlyOwnAccess dice si nadie más que el usuario puede tocar el archivo o carpeta. En Linux es lo mismo que IsPrivate.
// En Windows no exige dueño ni DACL protegida: basta que ninguna ACE (heredada o no) dé acceso a un SID que no sea el
// usuario, SYSTEM o Administradores. Es lo que cumple lo que se crea dentro de una carpeta hecha con MkdirPrivate.
func OnlyOwnAccess(path string) (bool, error) { return IsPrivate(path) }

// ReadOnlyDir deja la carpeta sin permiso de escritura (0500) y devuelve cómo restaurarla. Es para pruebas: en Windows
// chmod no cierra una carpeta, ahí se pone una ACE de «negar» escritura.
func ReadOnlyDir(path string) (restore func(), err error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o500); err != nil {
		return nil, err
	}
	return func() { os.Chmod(path, fi.Mode().Perm()) }, nil
}

// IsPrivate dice si el archivo o la carpeta no da acceso a grupo ni a otros. Es para pruebas.
func IsPrivate(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.Mode().Perm()&0o077 == 0, nil
}

// PrivateDir comprueba una carpeta de salidas ya resuelta (sin enlaces): del usuario, 0700 exacto y sin ancestros que
// otros puedan escribir. internal/service/outputs.go conserva su propia versión en Linux (con ganchos de prueba); esta
// es la misma regla con la API común de los dos sistemas.
func PrivateDir(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return &PrivateDirError{Reason: PrivateDirRead, Path: path, Err: err}
	}
	if uid, ok := Owner(fi); !ok || uid != uint32(os.Geteuid()) {
		return &PrivateDirError{Reason: PrivateDirOwner, Path: path}
	}
	if m := fi.Mode().Perm(); m != 0o700 {
		return &PrivateDirError{Reason: PrivateDirACL, Path: path, SID: m.String()}
	}
	for a := filepath.Dir(path); ; a = filepath.Dir(a) {
		fi, err := os.Lstat(a)
		if err != nil {
			return &PrivateDirError{Reason: PrivateDirRead, Path: a, Err: err}
		}
		uid, _ := Owner(fi)
		if fi.Mode()&0o022 != 0 && uid != uint32(os.Geteuid()) {
			return &PrivateDirError{Reason: PrivateDirAncestor, Path: a, SID: fi.Mode().String()}
		}
		if a == filepath.Dir(a) {
			return nil
		}
	}
}
