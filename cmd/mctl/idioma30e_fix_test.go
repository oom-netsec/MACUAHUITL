package main

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
)

// langExplicit corre cada caso con --lang es y con --lang en (nada depende del idioma por omisión).
func langExplicit(t *testing.T, cases []langCase) {
	t.Helper()
	t.Cleanup(func() { cli.SetLang("") })
	for _, tc := range cases {
		for _, l := range []struct{ lang, want string }{{"es", tc.es}, {"en", tc.en}} {
			out, err := mctl(t, "", append([]string{"--lang", l.lang}, tc.args...)...)
			got := out
			if err != nil {
				got += "\n" + err.Error()
			}
			if !strings.Contains(got, l.want) {
				t.Errorf("%s --lang %s: falta %q en %q", tc.name, l.lang, l.want, got)
			}
		}
	}
}

func TestMensajesSueltosDeChangeYCalc(t *testing.T) {
	startCore(t)
	_, here, _, _ := runtime.Caller(0)
	td := func(p string) string { return filepath.Join(filepath.Dir(here), "..", "..", "internal", p) }
	langExplicit(t, []langCase{
		{"calc clave", []string{"calc", "bgp", "--route", "name=A,frob=1", "--route", "name=B"}, `ruta "name=A,frob=1": clave "frob" desconocida`, `route "name=A,frob=1": unknown key "frob"`},
		{"compliance", []string{"compliance", "check", "--config", td("compliance/testdata/debil.txt"), "--template", td("compliance/testdata/plantilla.txt")}, " reglas fallaron", " rules failed"},
	})
}
