package transfer

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

// erroresEs reúne los errores de validación de transfer, en español.
func erroresEs(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	put := func(n string, err error) {
		out[n] = "ok"
		if err != nil {
			out[n] = err.Error()
		}
	}
	u := func(s string) *url.URL { x, _ := url.Parse(s); return x }
	for n, s := range map[string]string{"puerto": "ftp://h:99999/a", "esquema": "gopher://h/a", "cero": "ftp://h:0/a"} {
		_, err := Port(u(s))
		put("puerto_"+n, err)
	}
	for n, s := range map[string]string{"vacia": "ftp://h/", "caracter": "ftp://h/a b", "opcion": "scp://h/-x", "ok": "ftp://h/a.cfg"} {
		_, err := remotePath(u(s))
		put("ruta_"+n, err)
	}
	r := Request{Timeout: 99 * time.Hour}
	_, err := r.limits()
	put("tiempo", err)
	dest := t.TempDir()
	_, err = Download(context.Background(), Request{})
	put("descargar_sin_url", err)
	_, err = Download(context.Background(), Request{URL: u("gopher://h/a"), DestDir: dest})
	put("descargar_esquema", err)
	os.WriteFile(dest+"/a.cfg", []byte("x"), 0o600)
	_, err = Download(context.Background(), Request{URL: u("tftp://127.0.0.1:1/a.cfg"), DestDir: dest})
	put("descargar_existe", err)
	_, err = Upload(context.Background(), Request{})
	put("subir_sin_url", err)
	_, err = Browse(context.Background(), Request{}, "", 0)
	put("listar_sin_url", err)
	_, err = Browse(context.Background(), Request{URL: u("tftp://h/")}, "", 0)
	put("listar_tftp", err)
	_, err = Browse(context.Background(), Request{URL: u("ftp://h/")}, strings.Repeat("a", 5000), 0)
	put("listar_ruta_larga", err)
	_, err = Browse(context.Background(), Request{URL: u("ftp://h/")}, "a\x01b", 0)
	put("listar_ruta_control", err)
	_, err = Browse(context.Background(), Request{URL: u("gopher://h/")}, "", 0)
	put("listar_esquema", err)
	for k, v := range out {
		out[k] = strings.ReplaceAll(v, dest, "<dir>")
	}
	return out
}

func TestErroresEsRegresion(t *testing.T) {
	i18ntest.Golden(t, "testdata/transfer_es.golden.json", erroresEs(t))
}
