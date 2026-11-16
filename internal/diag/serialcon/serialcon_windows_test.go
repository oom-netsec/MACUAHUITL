//go:build windows

package serialcon

import "testing"

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
