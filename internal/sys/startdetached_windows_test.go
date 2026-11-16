package sys

import (
	"os"
	"testing"
)

// TestMain: con MCU_SYS_DETACHED_CHILD el binario de prueba hace de «núcleo» que sale enseguida.
func TestMain(m *testing.M) {
	if os.Getenv("MCU_SYS_DETACHED_CHILD") != "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStartDetachedLanzaElBinario(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("MCU_SYS_DETACHED_CHILD", "1")
	if err := StartDetached(exe); err != nil {
		t.Fatalf("StartDetached = %v", err)
	}
	if err := StartDetached(exe + ".no-existe.exe"); err == nil {
		t.Fatal("un exe que no existe debe dar el error de Start")
	}
}
