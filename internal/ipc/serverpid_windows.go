package ipc

import (
	"errors"
)

// ErrNotRunning: no hay un núcleo escuchando.
var ErrNotRunning = errors.New("ipc: el núcleo no está corriendo")

// ServerPID en Windows será GetNamedPipeServerProcessId sobre el pipe; llega con 43a4 (este paquete aún no compila
// en Windows).
func ServerPID(string) (int, error) { return 0, errors.ErrUnsupported }
