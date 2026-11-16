package sys

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestMain: con MCU_SYS_DETACHED_CHILD (un archivo) el binario de prueba hace de «núcleo»: escribe el marcador y sale.
func TestMain(m *testing.M) {
	if f := os.Getenv("MCU_SYS_DETACHED_CHILD"); f != "" {
		os.WriteFile(f, []byte("vivo"), 0o600)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestStartDetachedLanzaElBinario(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	marca := filepath.Join(t.TempDir(), "marca")
	t.Setenv("MCU_SYS_DETACHED_CHILD", marca)
	if err := StartDetached(exe); err != nil {
		t.Fatalf("StartDetached = %v", err)
	}
	for i := 0; ; i++ { // el hijo es otro proceso: se espera su marcador, con plazo
		if _, err := os.Stat(marca); err == nil {
			break
		}
		if i > 100 {
			t.Fatal("el hijo no escribió su marcador en 10 s")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := StartDetached(exe + ".no-existe.exe"); err == nil {
		t.Fatal("un exe que no existe debe dar el error de Start")
	}
}

func TestStartDetachedRechazaUNCyDispositivo(t *testing.T) {
	for _, p := range []string{`\\host\share\x.exe`, `\\.\pipe\x`} {
		if err := StartDetached(p); err == nil {
			t.Errorf("StartDetached(%q) no falló", p)
		}
	}
}
