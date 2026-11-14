package cli

import "testing"

func TestYesAceptaAfirmacionesEnEsYEn(t *testing.T) {
	for _, a := range []string{"s", "si", "sí", "y", "yes"} {
		if !yes(a) {
			t.Errorf("%q debía afirmar", a)
		}
	}
	for _, a := range []string{"", "n", "no", "yess", "ok"} {
		if yes(a) {
			t.Errorf("%q no debía afirmar", a)
		}
	}
}
