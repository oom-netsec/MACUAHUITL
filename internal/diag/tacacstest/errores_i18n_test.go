package tacacstest

import (
	"bytes"
	"context"
	"regexp"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

func erroresTacacs() map[string]error {
	ok := base("192.0.2.1", 49)
	m := map[string]error{}
	r := func(n string, f func(*Config)) {
		c := ok
		f(&c)
		_, m[n] = Run(context.Background(), nil, c)
	}
	r("servidor", func(c *Config) { c.Host = "" })
	r("secreto", func(c *Config) { c.Secret = nil })
	r("usuario", func(c *Config) { c.Username = "" })
	r("tipo", func(c *Config) { c.AuthenType = "chap" })
	r("av", func(c *Config) { c.Command = string(bytes.Repeat([]byte("a"), 300)) })
	_, _, m["version"] = readPacket(bytes.NewReader([]byte{0x31, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0}), nil)
	_, _, m["limite"] = readPacket(bytes.NewReader([]byte{0xc1, 1, 1, 1, 0, 0, 0, 1, 0, 2, 0, 0}), nil)
	_, m["truncado"] = parseAuthenReply([]byte{1})
	return m
}

func TestErroresTacacsEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for k, e := range erroresTacacs() {
		if e == nil {
			t.Fatalf("%s: debió fallar", k)
		}
		got[k] = e.Error()
	}
	i18ntest.Golden(t, "testdata/errores_es.golden.json", got)
}

var palabrasEs = regexp.MustCompile(`(?i)[áéíóúñ¿]|\b(inválid|falta|más de|vacío|no soportad|cuerpo|versión|usuario|servidor|secreto|excede|acorta|truncad)`)

func TestErroresTacacsEn(t *testing.T) {
	for k, e := range erroresTacacs() {
		if m := palabrasEs.FindString(i18n.English(e)); m != "" {
			t.Errorf("%s: queda español (%q): %s", k, m, i18n.English(e))
		}
	}
}
