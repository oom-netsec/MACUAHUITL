package fileserve

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

// 43d-1: nombres de red hostiles. Lo que pide el par por la red nunca sale de la carpeta ni abre
// nada que Windows interprete distinto (flujos, dispositivos, rutas de unidad). Se rechaza igual en
// todos los sistemas: ningún equipo legítimo manda estos nombres.

// Lo que SafeName debe neutralizar: se queda el nombre base y nada sale de la carpeta.
var neutralizados = map[string]string{
	"../x": "x", `..\x`: "x", `..\..\x`: "x", "/x": "x",
	`C:\x`: "x", `\\?\C:\x`: "x", `\\.\pipe\x`: "x", `\\host\share\x`: "x",
	"a/../x": "x", "PROGRA~1": "PROGRA~1", "FW~1.BIN": "FW~1.BIN", "ñandú-é.cfg": "ñandú-é.cfg", "設定.cfg": "設定.cfg",
}

// Lo que SafeName debe rechazar.
var rechazados = []string{
	"C:x", "a:b", "x:flujo:$DATA", "a:", `\\?\C:`, `\\.\pipe\`,
	"CON", "con", "NUL", "AUX", "PRN", "COM1", "LPT1", "COM9", "CONIN$", "CONOUT$",
	"con.txt", "NUL.", "Aux.cfg", "com1.txt", "LPT1.log", "nul .txt", "COM\u00b9", "LPT\u00b2.txt", "CON.tar.gz",
	"a.", "a..", "a ", "a. ", "a .",
	"a<b", "a>b", `a"b`, "a|b", "a?b", "a*b",
	"a\u202etxt.exe", "a\u2066b", "a\u2067b", "a\u2068b", "a\u2069b", "a\u200eb", "a\u200fb", "a\u061cb", "a\U000e0041b",
	"a\u0085b", "a\u2028b", "a\u2029b", "a\x00b", "a\x01b", "a\x1bb", "a\x7fb", "a\u0080b", "a\u009fb",
}

func TestSafeNameHostiles(t *testing.T) {
	for in, want := range neutralizados {
		if got, err := SafeName(in); err != nil || got != want {
			t.Errorf("SafeName(%q) = %q, %v; quería %q", in, got, err, want)
		}
	}
	for _, in := range rechazados {
		if got, err := SafeName(in); err == nil {
			t.Errorf("SafeName(%q) = %q, debió rechazarse", in, got)
		}
	}
	// Falsos positivos: nombres normales que contienen partes de los reservados.
	for _, in := range []string{"console.log", "connect", "nulo", "auxiliar.txt", "com10", "lpt", "com", "a.b", "a-b_c", "x (1).txt", "CONFIG"} {
		if _, err := SafeName(in); err != nil {
			t.Errorf("SafeName(%q) rechazó un nombre normal: %v", in, err)
		}
	}
}

func TestSafeNameLimiteDeBytes(t *testing.T) {
	for n, ok := range map[int]bool{199: true, 200: true, 201: false, 255: false} {
		if _, err := SafeName(strings.Repeat("a", n)); (err == nil) != ok {
			t.Errorf("%d bytes: err = %v", n, err)
		}
	}
	// Se cuentan bytes, no runas: 100 "ñ" son 200 bytes; 101 son 202.
	for n, ok := range map[int]bool{100: true, 101: false} {
		if _, err := SafeName(strings.Repeat("ñ", n)); (err == nil) != ok {
			t.Errorf("%d ñ: err = %v", n, err)
		}
	}
	if _, err := SafeName(strings.Repeat("設", 67)); err == nil { // 201 bytes
		t.Error("67 runas CJK (201 bytes) aceptadas")
	}
}

// plainName es la puerta de la lectura: mismas reglas de nombre que la escritura.
func TestPlainNameHostiles(t *testing.T) {
	for _, in := range append([]string{"..", ".", "", "a/b", `a\b`, "a\nb", "a\rb", "a\x00b", "a\x7fb"}, rechazados...) {
		if got, ok := plainName(in); ok {
			t.Errorf("plainName(%q) = %q, debió rechazarse", in, got)
		}
	}
	for _, in := range []string{"a.bin", "/a.bin", "ñandú.cfg", "PROGRA~1", "console.log", "running-config"} {
		if _, ok := plainName(in); !ok {
			t.Errorf("plainName(%q) rechazó un nombre normal", in)
		}
	}
}

// ---- por protocolo ----

type escenario struct {
	base, pub, recv string
}

// nuevoEscenario arma base/{pub,recv,secret}. pub trae ok.txt y los archivos de nombre hostil que el
// sistema deje crear (en Linux casi todos): ninguno de ellos debe servirse.
func nuevoEscenario(t *testing.T) escenario {
	t.Helper()
	b := realTemp(t)
	e := escenario{base: b, pub: filepath.Join(b, "pub"), recv: filepath.Join(b, "recv")}
	os.Mkdir(e.pub, 0o700)
	os.Mkdir(e.recv, 0o700)
	os.WriteFile(filepath.Join(b, "secret"), []byte("SECRET"), 0o600)
	os.WriteFile(filepath.Join(e.pub, "ok.txt"), []byte("OK"), 0o600)
	for _, n := range []string{"a:b", "con.txt", "nul", "a.", "x?y", "ñ.txt"} {
		os.WriteFile(filepath.Join(e.pub, n), []byte("HOSTIL"), 0o600) // en Windows falla y se omite
	}
	return e
}

// lecturas que no deben devolver nada. Incluye lo que en Windows apuntaría a otro lado.
var lecturasHostiles = []string{
	"../secret", `..\secret`, "/../secret", "secret", "../recv/x", `C:\secret`, "C:secret", `\\?\C:\secret`, `\\.\pipe\x`,
	`\\host\share\secret`, "ok.txt:flujo", "ok.txt::$DATA", "ok.txt.", "ok.txt ", "OK.TXT:x",
	"a:b", "con.txt", "nul", "a.", "x?y", "ok.txt\u202e", "\u202eok.txt", "ok.txt\u200e",
}

func (e escenario) revisaEscritura(t *testing.T) {
	t.Helper()
	if b, _ := os.ReadFile(filepath.Join(e.base, "secret")); string(b) != "SECRET" {
		t.Errorf("secret cambió: %q", b)
	}
	if ents, _ := os.ReadDir(e.base); len(ents) != 3 {
		t.Errorf("apareció algo fuera de la carpeta de recepción: %v", ents)
	}
	if b, err := os.ReadFile(filepath.Join(e.pub, "ok.txt")); err != nil || string(b) != "OK" {
		t.Errorf("ok.txt cambió: %q %v", b, err)
	}
	ents, _ := os.ReadDir(e.recv)
	for _, en := range ents {
		if n, err := SafeName(en.Name()); err != nil || n != en.Name() || slices.Contains(rechazados, en.Name()) {
			t.Errorf("se creó un archivo con nombre no válido: %q", en.Name())
		}
	}
}

// nombresDeEscritura son los de la tabla que no rompen el encuadre de ningún protocolo (sin controles ni NUL).
func nombresDeEscritura() []string {
	var out []string
	for in := range neutralizados {
		if in != "/x" && in != "a/../x" { // FTP/SCP los entienden como ruta: ya los cubren las pruebas viejas
			out = append(out, in)
		}
	}
	for _, in := range rechazados {
		if !strings.ContainsAny(in, "\x00\x01\x1b\x7f\u0085\u0080\u009f") {
			out = append(out, in)
		}
	}
	return out
}

func TestTFTPNombresHostiles(t *testing.T) {
	e := nuevoEscenario(t)
	s, _ := startCfg(t, Config{Proto: "tftp", FromDir: e.pub, Write: true, RecvDir: e.recv})
	for _, n := range nombresDeEscritura() {
		dialTFTP(t, s.addr).put(n, []byte("EVIL"), 512)
	}
	e.revisaEscritura(t)
	for _, n := range lecturasHostiles {
		c := dialTFTP(t, s.addr)
		c.send(c.srv, rrq(n))
		p, _ := c.recv()
		if p[1] != 5 {
			t.Errorf("TFTP RRQ %q: se sirvió algo (op %d, %q)", n, p[1], p[2:])
		}
	}
}

func TestFTPNombresHostiles(t *testing.T) {
	e := nuevoEscenario(t)
	s, r := startCfg(t, Config{Proto: "ftp", FromDir: e.pub, Write: true, RecvDir: e.recv})
	f := ftpDial(t, s.addr)
	f.login(r)
	f.cmd(200, "TYPE I")
	for _, n := range nombresDeEscritura() {
		if strings.ContainsAny(n, "\r\n") {
			continue
		}
		dc := f.pasv()
		f.tp.PrintfLine("STOR %s", n)
		code, _, _ := f.tp.ReadResponse(0)
		if code == 150 {
			dc.Write([]byte("EVIL"))
			dc.Close()
			f.tp.ReadResponse(0)
		}
	}
	e.revisaEscritura(t)
	for _, n := range lecturasHostiles {
		if strings.ContainsAny(n, "\r\n") {
			continue
		}
		dc := f.pasv()
		f.tp.PrintfLine("RETR %s", n)
		code, _, _ := f.tp.ReadResponse(0)
		if code == 150 {
			b, _ := io.ReadAll(dc)
			f.tp.ReadResponse(0)
			t.Errorf("FTP RETR %q: se sirvió %q", n, b)
		}
	}
}

func TestSCPNombresHostiles(t *testing.T) {
	e := nuevoEscenario(t)
	s, r := startCfg(t, Config{Proto: "scp", FromDir: e.pub, Write: true, RecvDir: e.recv})
	c := mustDial(t, s.addr, r)
	for _, n := range nombresDeEscritura() {
		if strings.ContainsAny(n, "\r\n") {
			continue
		}
		scpUpload(c, ".", n, []byte("EVIL"))
	}
	e.revisaEscritura(t)
	for _, n := range lecturasHostiles {
		if b, err := scpDownload(c, n); err == nil {
			t.Errorf("SCP -f %q: se sirvió %q", n, b)
		}
	}
	if b, err := scpDownload(c, "ok.txt"); err != nil || string(b) != "OK" {
		t.Errorf("ok.txt dejó de servirse: %q %v", b, err)
	}
}

func TestSFTPNombresHostiles(t *testing.T) {
	e := nuevoEscenario(t)
	s, r := startCfg(t, Config{Proto: "sftp", FromDir: e.pub, Write: true, RecvDir: e.recv})
	cl, err := sftp.NewClient(mustDial(t, s.addr, r))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	for _, n := range nombresDeEscritura() {
		if w, err := cl.Create("/" + n); err == nil {
			w.Write([]byte("EVIL"))
			w.Close()
		}
	}
	e.revisaEscritura(t)
	for _, n := range lecturasHostiles {
		if f, err := cl.Open("/" + n); err == nil {
			b, _ := io.ReadAll(f)
			f.Close()
			if len(b) > 0 {
				t.Errorf("SFTP open %q: se sirvió %q", n, b)
			}
		}
	}
}

func TestHTTPNombresHostiles(t *testing.T) {
	e := nuevoEscenario(t)
	s, _ := startCfg(t, Config{Proto: "http", FromDir: e.pub})
	base := "http://" + s.addr + "/"
	pedir := func(ruta string) (int, string) {
		r, err := http.Get(base + ruta)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()
		b, _ := io.ReadAll(r.Body)
		return r.StatusCode, string(b)
	}
	var rutas []string
	for _, n := range lecturasHostiles {
		rutas = append(rutas, url.PathEscape(n)) // el nombre tal cual, codificado
	}
	rutas = append(rutas, "%2e%2e%2fsecret", "..%2fsecret", "%2e%2e%5csecret", "..%5csecret", "%5c..%5csecret", "%2fsecret",
		"%2e%2e/secret", "a%2f..%2f..%2fsecret", "ok.txt%3Aflujo", "ok.txt%2e", "con%2etxt", "%00", "ok.txt%00.png", "%c0%ae%c0%ae/secret",
		"%e2%80%aeok.txt", "ok.txt%0d%0a", "%252e%252e%252fsecret")
	for _, ruta := range rutas {
		if code, body := pedir(ruta); code == 200 || strings.Contains(body, "SECRET") || strings.Contains(body, "HOSTIL") {
			t.Errorf("GET /%s: %d %q", ruta, code, body)
		}
	}
	if code, body := pedir("ok.txt"); code != 200 || !bytes.Equal([]byte(body), []byte("OK")) {
		t.Errorf("ok.txt: %d %q", code, body)
	}
	e.revisaEscritura(t) // GET no escribe: nada cambió
}
