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
