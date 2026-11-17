// Package testperm da a las pruebas la comprobación de «archivo privado» en cada sistema.
package testperm

import (
	"io/fs"
	"os"
	"runtime"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Private dice si el archivo o carpeta path es privado: en Linux, que su modo sea exactamente want (p. ej. 0o600); en
// Windows el modo POSIX no existe (Go da 0666 o 0444) y se mira la ACL (ADR 0012): ninguna ACE da acceso a otro SID
// (sys.OnlyOwnAccess). No exige la DACL protegida: lo creado dentro de una carpeta del usuario la hereda (para eso está systest).
func Private(path string, want fs.FileMode) bool {
	if runtime.GOOS == "windows" {
		ok, err := sys.OnlyOwnAccess(path)
		return err == nil && ok
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().Perm() == want
}
