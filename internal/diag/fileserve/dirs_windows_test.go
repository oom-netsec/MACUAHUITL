//go:build windows

package fileserve

import "testing"

// Los prefijos de dispositivo y las UNC no pasan por la lista de carpetas sensibles: se rechazan.
func TestWindowsRechazaPrefijosDeDispositivo(t *testing.T) {
	d := realTemp(t)
	for _, p := range []string{`\\?\` + d, `\\.\` + d, `\??\` + d} {
		if _, err := ValidateDir(p); err == nil {
			t.Errorf("%s debió rechazarse", p)
		}
	}
}
