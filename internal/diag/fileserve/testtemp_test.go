package fileserve

import (
	"path/filepath"
	"testing"
)

// realTemp es t.TempDir() ya resuelto: en Windows TEMP viene en formato corto (RUNNER~1) y validateDir devuelve la ruta
// larga, así que las pruebas comparan contra esta.
func realTemp(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}
