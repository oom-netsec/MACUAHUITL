package radiustest

import (
	"context"
	"errors"
	"regexp"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

func erroresRadius() map[string]error {
	ok := base("192.0.2.1", 1812)
	m := map[string]error{}
	r := func(n string, f func(*Config)) {
		c := ok
		f(&c)
		_, m[n] = Run(context.Background(), nil, c)
	}
	r("servidor", func(c *Config) { c.Host = "" })
	r("secreto", func(c *Config) { c.Secret = nil })
	r("nasip", func(c *Config) { c.NASIP = "::1" })
	r("largo", func(c *Config) { c.CalledStationID = string(make([]byte, 300)) })
	r("enum", func(c *Config) { c.NASPortType = "nada" })
	r("usuario", func(c *Config) { c.Username = "" })
	r("clave", func(c *Config) { c.Password = make([]byte, 200) })
	r("metodo", func(c *Config) { c.Method = "x" })
	_, m["corto"] = Decode([]byte{1})
	_, m["longitud"] = Decode(append([]byte{1, 1, 0, 5}, make([]byte, 16)...))
	_, m["atributo"] = Decode(append(append([]byte{1, 1, 0, 22}, make([]byte, 16)...), 1, 9))
	return m
}

func TestErroresRadiusEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for k, e := range erroresRadius() {
		if e == nil {
			t.Fatalf("%s: debió fallar", k)
		}
		got[k] = e.Error()
	}
	i18ntest.Golden(t, "testdata/errores_es.golden.json", got)
}

var palabrasEs = regexp.MustCompile(`(?i)[áéíóúñ¿]|\b(inválid|debe ser|falta|más de|vacío|desconocid|no soportad|paquete|longitud|atributo|usuario|contraseña|servidor|secreto|método)`)

func TestErroresRadiusEn(t *testing.T) {
	for k, e := range erroresRadius() {
		if m := palabrasEs.FindString(i18n.English(e)); m != "" {
			t.Errorf("%s: queda español (%q): %s", k, m, i18n.English(e))
		}
	}
	var c i18n.Coded
	if _, err := Run(context.Background(), nil, Config{}); !errors.As(err, &c) {
		t.Error("sin código")
	}
}

func TestValorTruncadoEn(t *testing.T) {
	d := truncated("VSA-9", []byte{1, 2})
	if d.Value != "0x0102 (truncado)" || d.ValueIn("en") != "0x0102 (truncated)" {
		t.Errorf("%q / %q", d.Value, d.ValueIn("en"))
	}
	m := Decoded{Name: "MS-CHAP2-Success", Text: i18n.Tx("radius.val.mschap_bad")}
	if got := m.ValueIn("en"); regexp.MustCompile(`servidor|contraseña`).MatchString(got) || got == "" {
		t.Errorf("%q", got)
	}
}
