//go:build !windows

package ipc

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Un socket que quedó de un núcleo muerto rechaza la conexión: no está corriendo, y no es un error.
func TestCoreRunningSocketHuerfano(t *testing.T) {
	p := sockPath(t)
	os.MkdirAll(filepath.Dir(p), 0o700)
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if up, err := coreRunning(p); up || err != nil {
		t.Fatalf("coreRunning = %v, %v; quería false, nil", up, err)
	}
}
