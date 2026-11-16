package sys

import (
	"os"
	"path/filepath"
	"testing"
)

// En Windows el solo hecho de no fallar es la prueba: os.Open(dir).Sync() daba «Access is denied».
func TestSyncDir(t *testing.T) {
	if err := SyncDir(t.TempDir()); err != nil {
		t.Fatalf("SyncDir: %v", err)
	}
}

func TestSyncDirInexistenteFallaEnLinuxYNoEnWindows(t *testing.T) {
	err := SyncDir(filepath.Join(t.TempDir(), "no-existe"))
	if _, lin := os.Stat("/proc"); lin == nil && err == nil {
		t.Fatal("en Linux una carpeta que no existe debe fallar")
	}
}
