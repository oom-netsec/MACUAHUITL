package bridge

import "testing"

func TestInitialSizeCabeEnLaPantalla(t *testing.T) {
	for _, c := range []struct{ ww, wh, w, h int }{
		{1920, 1050, 1280, 800}, // sobra espacio: el preferido
		{1366, 740, 1229, 666},  // 1366×768 con su panel: 90 % del área de trabajo
		{1024, 600, 960, 640},   // más chica que el mínimo: el mínimo
		{0, 0, 1280, 800},       // sin datos de pantalla
	} {
		if w, h := InitialSize(c.ww, c.wh); w != c.w || h != c.h {
			t.Errorf("InitialSize(%d, %d) = %d×%d; quiero %d×%d", c.ww, c.wh, w, h, c.w, c.h)
		}
	}
}
