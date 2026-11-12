package upgrade

import (
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

var spanish = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(falta|sin|salida|equipo|modo|imagen|las|los|del|para|con|hay|libre|guardada)\b`)

// Cada punto de la verificación sale en inglés sin español, con el mismo número de claves que de textos.
func TestInformeEnInglesYClaves(t *testing.T) {
	for _, f := range []string{"c9600-install-sso.txt", "isr4451-bundle.txt"} {
		r, err := Check(outputs(t, f), Image{File: "x.bin", Size: 1 << 40, MD5: "0123456789abcdef0123456789abcdef"}, "")
		if err != nil {
			t.Fatal(err)
		}
		keys := i18n.Localize(&r, i18n.Es)
		if len(keys) < 2*len(r.Items) {
			t.Errorf("%s: %d claves para %d puntos", f, len(keys), len(r.Items))
		}
		i18n.Localize(&r, i18n.En)
		for _, it := range r.Items {
			if m := spanish.FindString(it.Title + " " + it.Detail); m != "" {
				t.Errorf("%s %s: español (%s) en %q / %q", f, it.ID, m, it.Title, it.Detail)
			}
		}
		if m := spanish.FindString(r.Note); m != "" || r.Note[:4] != "Veri" {
			t.Errorf("nota: %q", r.Note)
		}
	}
}

func TestErroresDeEntradaCodificados(t *testing.T) {
	for _, c := range []struct {
		img    Image
		es, en string
	}{
		{Image{}, "upgrade: falta el nombre de la imagen", "upgrade: the image name is missing"},
		{Image{File: "a b.bin"}, "upgrade: el nombre de la imagen no lleva carpetas ni espacios", "upgrade: the image name cannot contain folders or spaces"},
		{Image{File: "a.bin", MD5: "zz"}, "upgrade: el MD5 esperado son 32 caracteres hexadecimales", "upgrade: the expected MD5 is 32 hexadecimal characters"},
		{Image{File: "a.bin", Size: -1}, "upgrade: tamaño negativo", "upgrade: negative size"},
	} {
		_, err := Check(map[string]string{}, c.img, "")
		co, ok := err.(i18n.Coded)
		if err == nil || !ok || err.Error() != c.es || co.Localize(i18n.En) != c.en {
			t.Errorf("%+v: %v", c.img, err)
		}
	}
}

// Los escenarios de la regresión recorren todos los detalles de la verificación.
func TestEscenariosCubrenTodosLosDetalles(t *testing.T) {
	_, ptrs := regCases(t)
	used := map[string]bool{}
	for _, v := range ptrs {
		for k := range i18n.UsedKeys(v) {
			used[k] = true
		}
	}
	for _, k := range i18n.Codes() {
		if strings.HasPrefix(k, "upgrade.detail.") && !used[k] {
			t.Errorf("ningún escenario de la regresión produce %s", k)
		}
	}
}
