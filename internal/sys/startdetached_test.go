package sys

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStartDetachedRechazaRutaRelativa(t *testing.T) {
	err := StartDetached("macuahuitld.exe")
	if !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("StartDetached(relativa) = %v, quería el error de ruta no absoluta", err)
	}
}

func TestStartDetachedLinuxNoLanzaNada(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("solo Linux")
	}
	exe, _ := os.Executable() // un archivo regular
	if err := StartDetached(exe); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("StartDetached = %v, quería ErrUnsupported (en Linux arranca systemd --user)", err)
	}
}

func TestStartDetachedSoloArchivosRegulares(t *testing.T) {
	d := t.TempDir()
	if err := StartDetached(d); !errors.Is(err, fs.ErrInvalid) {
		t.Fatalf("carpeta: %v, quería ErrInvalid", err)
	}
	if err := StartDetached(filepath.Join(d, "no-existe")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("inexistente: %v, quería ErrNotExist", err)
	}
}
