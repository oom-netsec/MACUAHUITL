package snmp

import (
	"context"
	"regexp"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

func erroresSNMP() map[string]error {
	out := map[string]error{}
	ctx := context.Background()
	g := func(n string, t Target, oids ...string) { _, out[n] = Get(ctx, t, oids) }
	ok := Target{Host: "192.0.2.1", Community: "x"}
	g("sin-oids", ok)
	g("destino", Target{}, "1.3")
	g("comunidad", Target{Host: "192.0.2.1"}, "1.3")
	g("auth", Target{Host: "192.0.2.1", Version: "3", AuthProto: "MD5"}, "1.3")
	g("priv", Target{Host: "192.0.2.1", Version: "3", AuthProto: "SHA", PrivProto: "DES"}, "1.3")
	g("v3", Target{Host: "192.0.2.1", Version: "3", AuthProto: "SHA", PrivProto: "AES"}, "1.3")
	g("version", Target{Host: "192.0.2.1", Version: "1"}, "1.3")
	out["perfil"] = Poll(ctx, ok, []string{"nada"}, 0, 1, nil)
	out["trap-v3"] = ListenTraps(ctx, TrapConfig{Addr: "127.0.0.1:0", V3: &Target{}})
	return out
}

func TestErroresSNMPEspanolRegresion(t *testing.T) {
	got := map[string]string{}
	for k, e := range erroresSNMP() {
		if e == nil {
			t.Fatalf("%s: debió fallar", k)
		}
		got[k] = e.Error()
	}
	i18ntest.Golden(t, "testdata/errores_es.golden.json", got)
}

var palabrasEs = regexp.MustCompile(`(?i)[áéíóúñ]|\b(inválid|no soportad|falta|destino|vac[ií]o|desconocid|requiere|sin |comunidad|perfil)`)

func TestErroresSNMPEn(t *testing.T) {
	for k, e := range erroresSNMP() {
		if m := palabrasEs.FindString(i18n.English(e)); m != "" {
			t.Errorf("%s: queda español (%q): %s", k, m, i18n.English(e))
		}
	}
}
