package sys

import (
	"errors"
	"io/fs"
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
	if err := StartDetached("/bin/true"); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("StartDetached = %v, quería ErrUnsupported (en Linux arranca systemd --user)", err)
	}
}
