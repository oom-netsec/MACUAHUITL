package serialcon

import (
	"errors"
	"os"
	"regexp"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
	"golang.org/x/sys/unix"
)

func erroresSerial() map[string]error {
	ok := Config{Path: "/dev/ttyUSB0", Baud: 9600, DataBits: 8, Parity: "none", StopBits: 1, Flow: "none"}
	m := map[string]error{}
	v := func(n string, f func(*Config)) { c := ok; f(&c); m[n] = c.validate() }
	v("ruta", func(c *Config) { c.Path = "/tmp/x" })
	v("velocidad", func(c *Config) { c.Baud = 7 })
	v("datos", func(c *Config) { c.DataBits = 9 })
	v("paridad", func(c *Config) { c.Parity = "x" })
	v("parada", func(c *Config) { c.StopBits = 3 })
	v("flujo", func(c *Config) { c.Flow = "x" })
	m["permiso"] = openErr("/dev/ttyUSB0", os.ErrPermission)
	m["ocupado"] = openErr("/dev/ttyUSB0", unix.EBUSY)
	m["no-existe"] = openErr("/dev/ttyUSB0", os.ErrNotExist)
	_, m["no-serie"] = Open(Config{Path: "/dev/null"})
	return m
}

func TestErroresSerialEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for k, e := range erroresSerial() {
		if e == nil {
			t.Fatalf("%s: debió fallar", k)
		}
		got[k] = e.Error()
	}
	i18ntest.Golden(t, "testdata/errores_es.golden.json", got)
}

var palabrasEs = regexp.MustCompile(`(?i)[áéíóúñ¿]|\b(inválid|no soportad|velocidad|bits de|paridad|dispositivo|permiso|agrega|existe|en uso|puerto|ocupad)`)

func TestErroresSerialEn(t *testing.T) {
	for k, e := range erroresSerial() {
		if m := palabrasEs.FindString(i18n.English(e)); m != "" {
			t.Errorf("%s: queda español (%q): %s", k, m, i18n.English(e))
		}
	}
	if !errors.Is(openErr("/dev/x", os.ErrPermission), ErrPermission) {
		t.Error("ErrPermission")
	}
}
