//go:build !windows

package ipc

import (
	"os"
	"path/filepath"
	"testing"
)

func sockPath(t *testing.T) string {
	// Ruta corta: sun_path tiene 108 bytes.
	d, err := os.MkdirTemp("", "mcu")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "run", "core.sock")
}

// 3.6: XDG_RUNTIME_DIR vacío o relativo no da una ruta de socket (sería relativa al directorio actual).
func TestSocketPathRechazaRuntimeVacioORelativo(t *testing.T) {
	for _, rt := range []string{"", "rel", ".", "./x", "../x", "run/user/1000", "~"} {
		t.Setenv("XDG_RUNTIME_DIR", rt)
		if p, err := SocketPath(); err == nil {
			t.Errorf("XDG_RUNTIME_DIR=%q aceptado: %q", rt, p)
		}
	}
}
