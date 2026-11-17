//go:build windows

package service

import (
	"errors"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// 2.4 en Windows de verdad: UNC y rutas de dispositivo se rechazan antes de tocar la ruta (no abre SMB). El host es de
// documentación (RFC 5737): si el rechazo llegara tarde, la prueba pasaría de 2 s esperando la red.
func TestCheckOutputsWindowsRealRechazaUNCYDispositivos(t *testing.T) {
	for _, dir := range []string{`\\192.0.2.1\x\out`, `//192.0.2.1/x/out`, `\\?\C:\Windows`, `\\?\UNC\192.0.2.1\x`, `\\.\pipe\x`, `\\.\C:\x`, `\??\C:\x`} {
		_, err := CheckOutputs(dir, NewCoreSettings("fabrica", t.TempDir()), true)
		var e *i18n.Error
		if !errors.As(err, &e) || e.Code != "prefs.outputs.sin_unidad" {
			t.Errorf("%q: %v", dir, err)
		}
	}
}
