package imgverify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

func erroresImg(t *testing.T) map[string]error {
	f := filepath.Join(t.TempDir(), "x.bin")
	os.WriteFile(f, []byte("x"), 0o600)
	m := map[string]error{}
	_, m["ruta"] = Check("rel", "", "")
	_, m["md5"] = Check(f, "zz", "")
	_, m["sha"] = Check(f, "", "ab")
	return m
}

func TestErroresImgEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for k, e := range erroresImg(t) {
		got[k] = e.Error()
	}
	i18ntest.Golden(t, "testdata/errores_es.golden.json", got)
}

func TestErroresImgEn(t *testing.T) {
	for k, e := range erroresImg(t) {
		if en := i18n.English(e); strings.ContainsAny(en, "áéíóúñ") || strings.Contains(en, "esperado") || strings.Contains(en, "ruta") {
			t.Errorf("%s: %q", k, en)
		}
	}
}
