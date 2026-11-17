package devices

import "testing"

// Las carpetas son únicas sin distinguir mayúsculas (44d): un archivo con «lab» frente a un host guardado en «Lab» es igual, no conflicto.
func TestSameCarpetaSinMayusculas(t *testing.T) {
	a := Host{Name: "r1", Address: "10.0.0.1", Port: 22, Folder: "Lab"}
	b := a
	b.Folder = "lab"
	if !Same(a, b) {
		t.Fatal("«Lab» y «lab» son la misma carpeta")
	}
	b.Folder = "Oficina"
	if Same(a, b) {
		t.Fatal("carpetas distintas no son iguales")
	}
}
