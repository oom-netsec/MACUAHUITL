package fileserve

import (
	"os"
	"path/filepath"
	"testing"
)

// Un archivo suelto con nombre inválido se rechaza al publicar, con un mensaje claro; no se anuncia sin servirse.
func TestPublishRechazaNombreInvalido(t *testing.T) {
	dir := realTemp(t)
	for _, n := range []string{"aux.cfg", "x\nreload"} {
		p := filepath.Join(dir, n)
		if os.WriteFile(p, []byte("x"), 0o600) != nil {
			continue // el sistema no admite ese nombre
		}
		_, _, err := publish([]string{p}, nil)
		if err == nil {
			t.Errorf("publish(%q) aceptado", n)
		}
	}
	ok := filepath.Join(dir, "ok.cfg")
	os.WriteFile(ok, []byte("x"), 0o600)
	if _, _, err := publish([]string{ok}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestOpenFromNombreInvalidoMensajeClaro(t *testing.T) {
	dir := realTemp(t)
	os.WriteFile(filepath.Join(dir, "aux.cfg"), []byte("x"), 0o600)
	_, _, err := OpenFrom(dir, "aux.cfg")
	if err == nil {
		t.Fatal("aceptado")
	}
	if got := err.Error(); !containsAny(got, "reservado", "reserved") {
		t.Errorf("mensaje poco claro: %q", got)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				return true
			}
		}
	}
	return false
}

// Carrera hidden/apertura: lo que se decide es el handle ya abierto, no un Lstat previo.
func TestWritingFileReconoceElHandle(t *testing.T) {
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
	fi, _ := os.Stat(filepath.Join(dir, "fw.bin"))
	if !r.writingFile(fi) {
		t.Fatal("no reconoce el archivo en escritura")
	}
	w.commit()
	if r.writingFile(fi) {
		t.Fatal("tras confirmar sigue en escritura")
	}
}

func TestOpenNoSirveElArchivoQueSeEscribe(t *testing.T) {
	dir := realTemp(t)
	r, err := newReceiver(dir, 1000, 10000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	src := &source{dir: dir, rcv: r}
	if src.root, err = os.OpenRoot(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(src.close)
	w, _ := r.create("fw.bin", 0)
	if f, _, err := src.open("fw.bin"); err == nil {
		f.Close()
		t.Fatal("sirvió el archivo a medias")
	}
	w.commit()
	f, _, err := src.open("fw.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
}
