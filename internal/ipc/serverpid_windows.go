package ipc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows"
)

// ServerPID es el PID del proceso que atiende el pipe name (GetNamedPipeServerProcessId), ya comprobado contra el SID
// del usuario. ErrNotRunning si el pipe no existe.
func ServerPID(name string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, pid, err := dialPipe(ctx, name)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
		return 0, ErrNotRunning
	}
	if err != nil {
		return 0, fmt.Errorf("ipc: %w", err)
	}
	c.Close()
	if pid == 0 {
		return 0, fmt.Errorf("ipc: el pipe %s devolvió un PID inválido", name)
	}
	return int(pid), nil
}
