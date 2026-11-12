package fileserve

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

// motivosEs reúne los motivos de rechazo y los errores de validación de fileserve, en español.
func motivosEs(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	var dirs []string
	tmp := func() string {
		d := t.TempDir()
		dirs = append(dirs, d)
		return d
	}
	defer func() {
		for k, v := range out {
			for _, d := range dirs {
				v = strings.ReplaceAll(v, d, "<dir>")
			}
			out[k] = v
		}
	}()
	put := func(n string, err error) {
		out[n] = "ok"
		if err != nil {
			out[n] = err.Error()
		}
	}
	for n, raw := range map[string]string{"vacio": "  ", "espacios": " a", "punto": ".bashrc", "largo": strings.Repeat("a", 201), "utf8": "a\xffb", "control": "a\x01b", "formato": "a\u202eb", "ok": "r1.cfg"} {
		_, err := SafeName(raw)
		put("nombre_"+n, err)
	}
	for n, a := range map[string]string{"sin_puerto": "127.0.0.1", "puerto_malo": "127.0.0.1:x", "privilegiado": "127.0.0.1:69", "host": "localhost:6969", "todas": "0.0.0.0:6969"} {
		put("addr_"+n, ValidateAddr(a, false))
	}
	d := tmp()
	file := filepath.Join(d, "f.txt")
	os.WriteFile(file, []byte("x"), 0o600)
	link := filepath.Join(d, "enlace")
	os.Symlink(d, link)
	for n, dir := range map[string]string{"relativa": "rel", "no_existe": filepath.Join(d, "no"), "archivo": file, "enlace": link, "sensible": "/etc", "raiz": "/"} {
		_, err := ValidateDir(dir)
		put("dir_"+n, err)
	}
	if h, err := os.UserHomeDir(); err == nil {
		_, e := ValidateDir(h)
		put("dir_home", e)
	}
	dup := filepath.Join(tmp(), "f.txt")
	os.WriteFile(dup, []byte("y"), 0o600)
	for n, c := range map[string]Config{
		"nada":         {Addr: "127.0.0.1:6969", Proto: "tftp"},
		"proto":        {Addr: "127.0.0.1:6969", Proto: "gopher", FromDir: d},
		"http_escribe": {Addr: "127.0.0.1:8080", Proto: "http", FromDir: d, Write: true},
		"pasivo":       {Addr: "127.0.0.1:2121", Proto: "ftp", FromDir: d, PassivePorts: [2]uint16{80, 90}},
		"tftp_allow":   {Addr: "127.0.0.1:6969", Proto: "tftp", Write: true, RecvDir: d},
		"archivo_rel":  {Addr: "127.0.0.1:6969", Proto: "tftp", Files: []string{"rel"}},
		"no_regular":   {Addr: "127.0.0.1:6969", Proto: "tftp", Files: []string{d}},
		"duplicado":    {Addr: "127.0.0.1:6969", Proto: "tftp", Files: []string{file, dup}},
	} {
		put("check_"+n, Check(c))
	}
	_, err := newReceiver("rel", 0, 0)
	put("recepcion_relativa", err)
	_, _, err = OpenFrom(d, "no-existe")
	put("abrir_no_existe", err)
	for n, line := range map[string]string{"larga": strings.Repeat("A", 5000), "control": "A\x01B", "corta": "X", "numeros": "AB1D"} {
		_, _, err := parseFTP(line)
		put("ftp_"+n, err)
	}
	for n, cmd := range map[string]string{"otro": "ls", "opcion": "scp -", "ambos": "scp -t -f x", "mala": "scp -z x", "falta": "scp -v x", "ruta": "scp -t 'a;b'", "control": "scp -t a\x01b"} {
		_, _, err := parseSCP(cmd)
		put("scp_"+n, err)
	}
	return out
}

func TestMotivosEsRegresion(t *testing.T) {
	i18ntest.Golden(t, "testdata/fileserve_es.golden.json", motivosEs(t))
}

// Todo motivo fijo que el código usa (lit("…")) y toda clave con argumentos (why("clave", …)) está en el catálogo, y la
// traducción sigue al Text del motivo, no al texto.
func TestMotivosDelCodigoEstanEnElCatalogo(t *testing.T) {
	litRe := regexp.MustCompile(`lit\("([^"]+)"\)`)
	whyRe := regexp.MustCompile(`why\("(\w+)"`)
	files, _ := filepath.Glob("*.go")
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		for _, m := range litRe.FindAllStringSubmatch(string(b), -1) {
			n++
			if lit(m[1]).Empty() {
				t.Errorf("%s: el motivo %q no tiene traducción", f, m[1])
			}
		}
		for _, m := range whyRe.FindAllStringSubmatch(string(b), -1) {
			n++
			if why(m[1]).In(i18n.En) == reasonCodes+m[1] {
				t.Errorf("%s: la clave %q no está en el catálogo", f, m[1])
			}
		}
	}
	if n < 20 {
		t.Fatalf("la búsqueda encontró solo %d motivos", n)
	}
	cases := map[string]Transfer{
		"method POST":                     {Error: "método POST", ReasonT: why("method", "method", "POST")},
		"shell rejected":                  {Error: "shell rechazado", ReasonT: why("request_rejected", "type", "shell")},
		"channel direct-tcpip rejected":   {Error: "canal direct-tcpip rechazado", ReasonT: why("channel_rejected", "type", "direct-tcpip")},
		"sftp Setstat rejected":           {Error: "sftp Setstat rechazado", ReasonT: why("sftp_rejected", "method", "Setstat")},
		"STOR rejected":                   {Error: "STOR rechazado", ReasonT: why("request_rejected", "type", "STOR")},
		"exec rejected: path not allowed": {Error: "exec rechazado: ruta no permitida", ReasonT: why("exec_rejected", "reason", "ruta no permitida", "reason_en", "path not allowed")},
		"origin not allowed":              {Error: "origen no permitido", ReasonT: lit("origen no permitido")},
		"HTTP 404":                        {Error: "HTTP 404"},
	}
	for want, tr := range cases {
		if got := ReasonIn(i18n.En, tr); got != want || ReasonIn(i18n.Es, tr) != tr.Error {
			t.Errorf("%q: en %q", tr.Error, got)
		}
	}
}

// Una entrada enorme del cliente (el tipo de una petición SSH llega a 256 KB) no cuesta más que su longitud.
func TestMotivoConEntradaEnormeEsLineal(t *testing.T) {
	big := strings.Repeat("exec rechazado: ", 16000)
	start := time.Now()
	for i := 0; i < 20; i++ {
		tr := Transfer{Error: big + " rechazado", ReasonT: why("request_rejected", "type", big)}
		if got := ReasonIn(i18n.En, tr); !strings.HasSuffix(got, " rejected") {
			t.Fatalf("got %.40q", got)
		}
		_ = ReasonIn(i18n.En, Transfer{Error: big})
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("tardó %s", d)
	}
}

// Con en, los errores de validación y los nombres rechazados salen en inglés, con su código.
func TestValidacionEnIngles(t *testing.T) {
	es := motivosEs(t)
	ctxEn := func(err error) string { return i18n.In(i18n.En, err) }
	for n, f := range map[string]func() error{
		"dir": func() error { _, e := ValidateDir("/etc"); return e }, "nombre": func() error { _, e := SafeName(".x"); return e },
		"addr": func() error { return ValidateAddr("127.0.0.1:69", false) }, "check": func() error { return Check(Config{Addr: "127.0.0.1:6969", Proto: "tftp"}) },
	} {
		err := f()
		var c i18n.Coded
		if err == nil || !errors.As(err, &c) || ctxEn(err) == err.Error() || regexp.MustCompile(`[áéíóúñ¿]`).MatchString(ctxEn(err)) {
			t.Errorf("%s: %v / %q", n, err, ctxEn(err))
		}
	}
	_ = es
}
