// Package testperm da a las pruebas la comprobación de «archivo privado» en cada sistema.
package testperm

import (
	"io/fs"
	"runtime"
)

// Private dice si el modo de fi es el privado esperado (want, p. ej. 0o600). En Windows el modo POSIX no existe
// (Go da 0666 o 0444): la privacidad es la ACL (ADR 0012) y no se mide con el modo, así que ahí siempre es true.
func Private(fi fs.FileInfo, want fs.FileMode) bool {
	return runtime.GOOS == "windows" || fi.Mode().Perm() == want
}
