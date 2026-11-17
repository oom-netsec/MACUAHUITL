// Package testperm da a las pruebas la comprobación de «archivo privado» en cada sistema.
package testperm

import (
	"io/fs"
	"os"
	"runtime"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Private dice si el archivo o carpeta path es privado: en Linux, que su modo sea exactamente want (p. ej. 0o600); en
// Windows el modo POSIX no existe (Go da 0666 o 0444) y la privacidad es la ACL (ADR 0012), así que se pregunta a sys.IsPrivate.
func Private(path string, want fs.FileMode) bool {
	if runtime.GOOS == "windows" {
		ok, err := sys.IsPrivate(path)
		return err == nil && ok
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().Perm() == want
}
