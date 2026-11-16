//go:build windows

package serialcon

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// En el runner no hay puertos: basta con que la lectura real del registro no falle ni devuelva basura.
func TestListRegistroReal(t *testing.T) {
	for _, n := range List() {
		if _, ok := comNum(n); !ok {
			t.Errorf("valor inesperado %q", n)
		}
	}
}

func TestOpenAbsentePuertoNoExiste(t *testing.T) {
	if _, err := Open(Config{Path: "COM250"}); err == nil {
		t.Fatal("COM250 no debería abrir")
	}
	if _, err := Open(Config{Path: `C:\x`}); err == nil {
		t.Fatal("ruta arbitraria aceptada")
	}
}

// Un COM abierto por otra app (ACCESS_DENIED o SHARING_VIOLATION) es «en uso», como EBUSY en Linux; no un permiso.
func TestOpenErrEnUso(t *testing.T) {
	for _, e := range []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION} {
		var ie *i18n.Error
		if err := openErr(`\\.\COM3`, e); !errors.As(err, &ie) || ie.Code != "serial.err.busy" {
			t.Errorf("%v: %v", e, err)
		}
	}
	var ie *i18n.Error
	if err := openErr(`\\.\COM3`, windows.ERROR_FILE_NOT_FOUND); !errors.As(err, &ie) || ie.Code != "serial.err.missing" {
		t.Errorf("no existe: %v", err)
	}
}
