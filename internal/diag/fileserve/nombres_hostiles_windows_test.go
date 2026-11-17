//go:build windows

package fileserve

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// B1: lo recibido por la red lleva la Mark of the Web; el flujo lo escribe el código con la ruta interna.
func TestWindowsRecepcionEscribeMarkOfTheWeb(t *testing.T) {
	dir := realTemp(t)
	r, err := newReceiver(dir, 1000, 10000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	w, err := r.create("fw.bin", 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("datos"))
	if _, _, err := w.commit(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "fw.bin") + ":Zone.Identifier")
	if err != nil {
		t.Skip("el volumen no admite flujos alternos:", err)
	}
	if string(b) != "[ZoneTransfer]\r\nZoneId=3\r\n" {
		t.Fatalf("flujo = %q", b)
	}
}

// Con la API real: ningún nombre hostil crea nada, ni un flujo oculto, ni sale de la carpeta.
func TestWindowsCreateRechazaNombresHostiles(t *testing.T) {
	dir := realTemp(t)
	r, err := newReceiver(dir, 1000, 10000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	for _, n := range rechazados {
		if w, err := r.create(n, 0); err == nil {
			w.abort()
			t.Errorf("create(%q) aceptado", n)
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Fatalf("quedó algo en la carpeta: %v", ents)
	}
	for in, want := range neutralizados {
		w, err := r.create(in, 0)
		if err != nil {
			t.Errorf("create(%q): %v", in, err)
			continue
		}
		w.abort()
		if _, err := os.Lstat(filepath.Join(dir, want)); err == nil {
			t.Errorf("abort de %q dejó el archivo", in)
		}
	}
}

// B2 con Windows real: mientras se sube FW.BIN, otra capitalización y el nombre corto no sirven el archivo a medias.
func TestWindowsNoSirveElArchivoAMediasConOtroNombre(t *testing.T) {
	dir := realTemp(t)
	rx, err := newReceiver(dir, 1000, 10000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rx.close)
	src := &source{dir: dir, rcv: rx}
	if src.root, err = os.OpenRoot(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.close)
	w, err := rx.create("FW.BIN", 0)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("a medias"))
	alias := []string{"fw.bin", "Fw.Bin"}
	if long, err := syscall.UTF16PtrFromString(filepath.Join(dir, "FW.BIN")); err == nil {
		buf := make([]uint16, 300)
		if n, _ := syscall.GetShortPathName(long, &buf[0], uint32(len(buf))); n > 0 && n < uint32(len(buf)) {
			alias = append(alias, filepath.Base(syscall.UTF16ToString(buf[:n])))
		}
	}
	for _, n := range alias {
		if src.exists(n) {
			t.Errorf("exists(%q) dijo que el archivo a medias está publicado", n)
		}
		if f, _, err := src.open(n); err == nil {
			f.Close()
			t.Errorf("open(%q) abrió el archivo a medias", n)
		}
	}
	if _, _, err := w.commit(); err != nil {
		t.Fatal(err)
	}
	if !src.exists("fw.bin") {
		t.Error("ya confirmado debe servirse con cualquier capitalización")
	}
}
