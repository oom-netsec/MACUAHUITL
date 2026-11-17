// Package ipctest da a las pruebas una dirección de canal del núcleo que sirve en
// cada sistema: socket en la carpeta dada en Linux y macOS, y un named pipe único
// en Windows (donde una ruta de archivo no es un pipe).
package ipctest

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
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

// Isolate da a la prueba su propio pipe para ipc.SocketPath en Windows (pruebas de otros paquetes corren a la vez);
// en Linux y macOS no hace nada: ahí cada prueba apunta XDG_RUNTIME_DIR a su carpeta. Las pruebas que la usan no son paralelas.
func Isolate(t testing.TB) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	prev := ipc.TestPipeSuffix
	ipc.TestPipeSuffix = fmt.Sprintf("-test-%d-%d", os.Getpid(), seq.Add(1))
	t.Cleanup(func() { ipc.TestPipeSuffix = prev })
}

// SilentUDP escucha en 127.0.0.1 un puerto UDP que nunca contesta y devuelve su dirección host:puerto.
func SilentUDP(t testing.TB) string {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c.LocalAddr().String()
}
