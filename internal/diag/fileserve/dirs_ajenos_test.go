package fileserve

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// fijaEscritores simula quién más escribe en la carpeta (en Windows, SID) y que el sistema es Windows (orden icacls).
func fijaEscritores(t *testing.T, w sys.Writers, err error) {
	t.Helper()
	old, oldOS := foreignWriters, goos
	foreignWriters = func(string) (sys.Writers, error) { return w, err }
	goos = "windows"
	t.Cleanup(func() { foreignWriters, goos = old, oldOS })
}

func cfgRecv(dir string) Config {
	return Config{Addr: "127.0.0.1:6969", Proto: "ftp", Write: true, RecvDir: dir}
}

// 2.3 (decidido por Release): la carpeta de RECEPCIÓN con una ACE de escritura para un SID ajeno se RECHAZA, con la orden icacls.
func TestRecepcionConEscritorAjenoSeRechazaConIcacls(t *testing.T) {
	dir := realTemp(t)
	const user = "S-1-5-21-1-2-3-1001"
	fijaEscritores(t, sys.Writers{Who: []string{"S-1-1-0", "S-1-5-32-545"}, User: user}, nil)
	err := Check(cfgRecv(dir))
	var e *i18n.Error
	if !errors.As(err, &e) || e.Code != "fileserve.err.recv_dir_open_cmd" {
		t.Fatalf("%v", err)
	}
	for _, loc := range []string{i18n.Es, i18n.En} {
		m := e.Localize(loc)
		for _, want := range []string{`icacls "` + dir + `" /inheritance:r /remove "*S-1-1-0" /remove "*S-1-5-32-545" /grant:r "*` + user + `:(OI)(CI)F"`, "S-1-1-0"} {
			if !strings.Contains(m, want) {
				t.Errorf("%s: falta %q en %q", loc, want, m)
			}
		}
	}
	if !strings.Contains(e.Localize(i18n.En), "plant") || !strings.Contains(e.Localize(i18n.Es), "plantar") {
		t.Errorf("textos: %q / %q", e.Localize(i18n.En), e.Localize(i18n.Es))
	}
}

// Sin orden cuando la ruta o el SID no son seguros de pegar: solo el motivo.
func TestRecepcionConEscritorAjenoSinOrdenSiNoEsSeguro(t *testing.T) {
	base := realTemp(t)
	dir := filepath.Join(base, "a%TEMP%")
	if runtime.GOOS == "windows" {
		dir = filepath.Join(base, "a$b") // % es válido en Windows pero se prueba también con $
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, w := range []sys.Writers{
		{Who: []string{"S-1-1-0"}, User: "S-1-5-21-1-2-3-1001"},             // ruta con %
		{Who: []string{`S-1-1-0" & calc & "`}, User: "S-1-5-21-1-2-3-1001"}, // SID falso
		{Who: []string{"S-1-1-0"}, User: ""},                                // sin SID del usuario
	} {
		fijaEscritores(t, w, nil)
		d := dir
		if w.Who[0] != "S-1-1-0" || w.User == "" { // las dos últimas filas con ruta segura: el SID es lo hostil
			d = realTemp(t)
		}
		err := Check(cfgRecv(d))
		var e *i18n.Error
		if !errors.As(err, &e) || e.Code != "fileserve.err.recv_dir_open" || strings.Contains(e.Localize(i18n.En), "icacls") {
			t.Errorf("%+v: %v", w, err)
		}
	}
}

// Sin escritores ajenos la recepción abre normal; y si no se puede leer la ACL no se bloquea (no se sabe).
func TestRecepcionSinEscritoresAjenosAbre(t *testing.T) {
	dir := realTemp(t)
	fijaEscritores(t, sys.Writers{User: "S-1-5-21-1-2-3-1001"}, nil)
	if err := Check(cfgRecv(dir)); err != nil {
		t.Fatal(err)
	}
	fijaEscritores(t, sys.Writers{}, errors.New("sin ACL (FAT)"))
	if err := Check(cfgRecv(dir)); err != nil {
		t.Fatalf("sin poder leer la ACL no se bloquea: %v", err)
	}
}

// PUBLICACIÓN (--from): no se rechaza; el aviso va en la ayuda del servidor (el canal que ven mctl y la UI), en inglés
// canónico y en español.
func TestPublicacionConEscritorAjenoSoloAvisa(t *testing.T) {
	dir := realTemp(t)
	fijaEscritores(t, sys.Writers{Who: []string{"S-1-1-0"}, User: "S-1-5-21-1-2-3-1001"}, nil)
	c := Config{Addr: "127.0.0.1:6969", Proto: "tftp", FromDir: dir}
	if err := Check(c); err != nil {
		t.Fatalf("la publicación no se rechaza: %v", err)
	}
	en := ServerHintIn(i18n.En, c, Ready{Addr: c.Addr}, nil)
	if !strings.Contains(en, "another user can replace the files you serve (for example, a firmware image)") || !strings.Contains(en, `icacls "`+dir+`"`) {
		t.Errorf("en: %s", en)
	}
	es := ServerHintIn(i18n.Es, c, Ready{Addr: c.Addr}, nil)
	if !strings.Contains(es, "otro usuario puede reemplazar los archivos que sirves (por ejemplo, una imagen de firmware)") {
		t.Errorf("es: %s", es)
	}
	fijaEscritores(t, sys.Writers{}, nil)
	if h := ServerHintIn(i18n.En, c, Ready{Addr: c.Addr}, nil); strings.Contains(h, "firmware image") {
		t.Errorf("sin escritores ajenos no hay aviso: %s", h)
	}
}

// Linux: el bit de otros de verdad (el de grupo depende del grupo de la carpeta: ver sys/private_linux_test.go).
func TestRecepcionYPublicacionLinuxBitDeOtros(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("bits POSIX")
	}
	dir := filepath.Join(realTemp(t), "r")
	os.Mkdir(dir, 0o700)
	os.Chmod(dir, 0o707)
	err := Check(cfgRecv(dir))
	var e *i18n.Error
	if !errors.As(err, &e) || e.Code != "fileserve.err.recv_dir_open_cmd" || !strings.Contains(e.Localize(i18n.En), "chmod o-w "+dir) {
		t.Errorf("0707: %v", err)
	}
	c := Config{Addr: "127.0.0.1:6969", Proto: "tftp", FromDir: dir}
	if err := Check(c); err != nil {
		t.Errorf("publicación: %v", err)
	}
	if h := ServerHintIn(i18n.En, c, Ready{Addr: c.Addr}, nil); !strings.Contains(h, "firmware image") || !strings.Contains(h, "chmod o-w "+dir) {
		t.Errorf("aviso: %s", h)
	}
	for _, modo := range []os.FileMode{0o700, 0o750, 0o755} { // lectura de otros no es escritura
		os.Chmod(dir, modo)
		if err := Check(cfgRecv(dir)); err != nil {
			t.Errorf("%o debía abrir: %v", modo, err)
		}
	}
}
