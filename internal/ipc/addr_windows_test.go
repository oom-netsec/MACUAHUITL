package ipc

import (
	"fmt"
	"os"
	"testing"
	"time"
)

// sockPath es un nombre de pipe único por prueba (el pipe del usuario real no se toca).
func sockPath(t *testing.T) string {
	return fmt.Sprintf(`\\.\pipe\macuahuitl-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
}
