// Package ipctest da a las pruebas una dirección de canal del núcleo que sirve en
// cada sistema: socket en la carpeta dada en Linux y macOS, y un named pipe único
// en Windows (donde una ruta de archivo no es un pipe).
package ipctest

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
)

var seq atomic.Int64

// Addr devuelve la dirección para escuchar y marcar en una prueba. En Windows
// ignora dir y da un pipe distinto en cada llamada, para no tocar el del usuario.
func Addr(dir string) string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf(`\\.\pipe\macuahuitl-test-%d-%d`, os.Getpid(), seq.Add(1))
	}
	return filepath.Join(dir, "core.sock")
}
