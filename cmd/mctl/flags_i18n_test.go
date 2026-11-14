package main

import (
	"bufio"
	"flag"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// españolEnBandera son letras y palabras que no deben quedar en la descripción en inglés de una bandera.
var españolEnBandera = regexp.MustCompile(`(?i)[áéíóúñ¿¡]|\b(sin|ningún|equipo|equipos|tiene|puerto|las|los|del|una|con|por|para|según|línea|líneas|regla|reglas|salida|archivo|ruta|nombre|valor|por defecto|segundos|cada)\b`)

// flagSets recorre los comandos reales de todas las áreas (las de main.go) con -h y devuelve el FlagSet de cada uno.
func flagSets(t *testing.T) map[string]*flag.FlagSet {
	t.Helper()
	got := map[string]*flag.FlagSet{}
	cli.FlagSetHook = func(name string, fs *flag.FlagSet) { got[name] = fs }
	cli.HelpOut = io.Discard
	t.Cleanup(func() { cli.FlagSetHook, cli.HelpOut = nil, os.Stdout })
	for _, a := range areas {
		for _, c := range a.Commands {
			func() {
				defer func() { _ = recover() }() // sin banderas, algunos comandos tocan la conexión antes de leer -h
				_ = c.Run(&cli.Env{In: bufio.NewReader(strings.NewReader("")), Out: io.Discard}, []string{"-h"})
			}()
		}
	}
	if len(got) < 100 {
		t.Fatalf("solo %d comandos con banderas: ¿se perdió el recorrido?", len(got))
	}
	return got
}

// Toda bandera de todo comando tiene su descripción en inglés y en español en el catálogo, y la inglesa no deja español.
func TestBanderasConDescripcionEnAmbosIdiomas(t *testing.T) {
	var n int
	for name, fs := range flagSets(t) {
		fs.VisitAll(func(f *flag.Flag) {
			n++
			var en, es string
			for _, code := range []string{cli.FlagCode(name, f.Name), "mctl.flag." + f.Name} {
				if i18n.Msg(i18n.En, code, nil) != code {
					en, es = i18n.Msg(i18n.En, code, nil), i18n.Msg(i18n.Es, code, nil)
					break
				}
			}
			if en == "" || es == "" {
				t.Errorf("mctl %s --%s: falta la descripción en inglés o en español", name, f.Name)
				return
			}
			if m := españolEnBandera.FindString(en); m != "" {
				t.Errorf("mctl %s --%s: español en el inglés: %q (%s)", name, f.Name, en, m)
			}
		})
	}
	t.Logf("%d banderas", n)
}

// mctl <área> <cmd> -h (o --help) escribe las banderas con su descripción en el idioma de mctl, sale sin error y sin
// conectar al núcleo (aquí no hay socket).
func TestAyudaDeBanderasSigueElIdioma(t *testing.T) {
	for _, c := range []struct {
		cmd  []string
		en   string
		es   string
		flag string
	}{
		{[]string{"syslog", "listen"}, "listen address", "dirección de escucha", "-addr"},
		{[]string{"calc", "mtu"}, "physical IP MTU", "MTU IP física", "-mtu"},
		{[]string{"dns", "trace"}, "request DNSSEC records", "pide registros DNSSEC", "-dnssec"},
	} {
		for _, h := range []string{"-h", "--help"} {
			t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
			en, err := mctlRaw(t, "", append(append([]string{}, c.cmd...), h)...)
			if err != nil || !strings.Contains(en, "usage: mctl "+strings.Join(c.cmd, " ")) || !strings.Contains(en, c.en) || !strings.Contains(en, c.flag) {
				t.Errorf("%v %s en: err=%v\n%s", c.cmd, h, err, en)
			}
			es, err := mctlRaw(t, "", append([]string{"--lang", "es"}, append(append([]string{}, c.cmd...), h)...)...)
			if err != nil || !strings.Contains(es, "uso: mctl "+strings.Join(c.cmd, " ")) || !strings.Contains(es, c.es) {
				t.Errorf("%v %s es: err=%v\n%s", c.cmd, h, err, es)
			}
		}
	}
}
