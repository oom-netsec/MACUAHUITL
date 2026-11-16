//go:build !windows

package ipc

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ServerPID es el PID del proceso que escucha en el socket path: SO_PEERCRED leído del lado del cliente.
// ErrNotRunning si el socket no existe o rechaza la conexión.
// shortcut: el PID puede reutilizarse entre esta lectura y WaitExit (ventana de milisegundos); en el peor caso core stop
// espera de más y sale con 1.
// En Windows es serverpid_windows.go: GetNamedPipeServerProcessId sobre el pipe.
func ServerPID(path string) (int, error) { return serverPID(path, os.Getuid()) }

func serverPID(path string, uid int) (int, error) {
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return 0, ErrNotRunning
	}
	if err != nil {
		return 0, fmt.Errorf("ipc: %w", err)
	}
	defer c.Close()
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("ipc: %w", err)
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return 0, fmt.Errorf("ipc: %w", err)
	}
	if cerr != nil {
		return 0, fmt.Errorf("ipc: %w", cerr)
	}
	if int(cred.Uid) != uid || cred.Pid <= 0 { // el socket lo escucha otro usuario: no es nuestro núcleo
		return 0, i18n.New("ipc.err.socket_other_user", i18n.A("path", path))
	}
	return int(cred.Pid), nil
}
