package fileserve

import (
	"os"
	"path/filepath"
	"testing"
)

// B2: "en escritura" se decide por identidad del archivo, no por el nombre exacto. En Windows
// "fw.bin" y "FW~1.BIN" son el mismo archivo que "FW.BIN"; aquí un enlace duro hace de alias en
// cualquier sistema (la gemela de Windows usa mayúsculas y nombre corto reales).
func TestEnEscrituraPorIdentidadNoPorNombre(t *testing.T) {
	dir := realTemp(t)
	r, err := newReceiver(dir, 1000, 10000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	w, err := r.create("FW.BIN", 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("a medias"))
	if err := os.Link(filepath.Join(dir, "FW.BIN"), filepath.Join(dir, "alias")); err != nil {
		t.Skip("sin enlaces duros:", err)
	}
	if !r.writing("FW.BIN") || !r.writing("alias") {
		t.Fatal("el archivo a medias no se reconoce por su otro nombre")
	}
	if r.writing("otro") {
		t.Error("un nombre inexistente figura en escritura")
	}
	if _, _, err := w.commit(); err != nil {
		t.Fatal(err)
	}
	if r.writing("alias") || r.writing("FW.BIN") {
		t.Error("tras confirmar sigue figurando en escritura")
	}
}
