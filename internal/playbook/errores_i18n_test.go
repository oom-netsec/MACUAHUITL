package playbook

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

// erroresPlaybook arma cada error de CheckDenied, Ephemeral y Load; devuelve el texto en es y el error.
func erroresPlaybook(t *testing.T) (map[string]string, map[string]error) {
	t.Helper()
	texts, errs := map[string]string{}, map[string]error{}
	put := func(n string, err error) {
		if err == nil {
			t.Errorf("%s: debió fallar", n)
			return
		}
		errs[n], texts[n] = err, err.Error()
	}
	for n, c := range map[string]string{
		"deny-ascii": "show version\x0dconfigure terminal", "deny-terminal": "terminal shell", "deny-escritura": "configure terminal",
		"deny-pipe-vacio": "show version | ", "deny-redirect": "show version | redirect flash:x", "deny-filtro": "show version | foo bar",
		"deny-no-ascii": "show versión",
	} {
		put(n, CheckDenied("ios", c))
	}
	_, err := Ephemeral("ios", "show clock\nshow a\rshow b")
	put("ephemeral-cr", err)
	_, err = Ephemeral("ios", "configure terminal")
	put("ephemeral-deny", err)
	_, err = Ephemeral("ios", "! solo comentario\n\n")
	put("ephemeral-vacio", err)
	load := func(n, yaml string) {
		_, err := Load(fstest.MapFS{"a.yaml": {Data: []byte(yaml)}})
		put(n, err)
	}
	load("load-obligatorios", "id: x\n")
	load("load-sin-comandos", "id: x\nplatform: ios\nname: X\ncommands: []\n")
	load("load-plataforma", "id: x\nplatform: ios\nname: X\ncommands:\n  - cmd: show clock\n    platforms: [nope]\n")
	load("load-vacio", "id: x\nplatform: ios\nname: X\ncommands:\n  - cmd: \"  \"\n")
	load("load-timeout", "id: x\nplatform: ios\nname: X\ncommands:\n  - cmd: show clock\n    timeout: abc\n")
	load("load-denegado", "id: x\nplatform: ios\nname: X\ncommands:\n  - cmd: configure terminal\n")
	return texts, errs
}

func TestErroresPlaybookEspanolRegresion(t *testing.T) {
	texts, _ := erroresPlaybook(t)
	i18ntest.Golden(t, "testdata/errores_es.golden.json", texts)
}

// Con en, los errores salen en inglés, conservan errors.Is(ErrDenied) y el texto de es no cambia.
var quoted = regexp.MustCompile(`"[^"]*"`)

func TestErroresPlaybookEn(t *testing.T) {
	_, errs := erroresPlaybook(t)
	spanish := regexp.MustCompile(`(?i)[áéíóúñ]|\b(comando|solo|lectura|retorno|pipe vacío|escriben|tras|obligatorios|sin comandos|desconocida|inválido|vacío|línea|dentro)\b`)
	for n, err := range errs {
		en := i18n.In("en", err)
		if en == err.Error() || spanish.MatchString(quoted.ReplaceAllString(en, `""`)) { // lo citado es un dato

			t.Errorf("%s: %q", n, en)
		}
		if strings.HasPrefix(n, "deny-") || n == "ephemeral-cr" || n == "ephemeral-deny" {
			if !errors.Is(err, ErrDenied) {
				t.Errorf("%s: ya no es ErrDenied", n)
			}
		}
	}
	if en := i18n.In("en", errs["deny-escritura"]); en != `playbook: command not allowed in a collection (read-only): "configure terminal" (not a read command)` {
		t.Errorf("en: %q", en)
	}
}
