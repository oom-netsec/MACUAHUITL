package main

import (
	"os"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
)

// La ayuda es contrato: testdata/help.golden es el texto de --help (con salto final).
func TestHelpGolden(t *testing.T) {
	want, err := os.ReadFile("testdata/help.golden")
	if err != nil {
		t.Fatal(err)
	}
	for _, arg := range []string{"--help", "-h", "help"} {
		if out := must(t, "", arg); out != string(want) {
			t.Fatalf("mctl %s: la ayuda cambió:\n%s", arg, out)
		}
	}
	// Sin comando, con comando desconocido o incompleto: el mismo texto como error, sin salto final.
	for _, args := range [][]string{nil, {"--no-color"}, {"frob", "x"}, {"vault"}, {"vault", "frob"}} {
		t.Setenv("XDG_RUNTIME_DIR", "")
		_, err := mctl(t, "", args...)
		if err == nil || err.Error() != strings.TrimSuffix(string(want), "\n") {
			t.Fatalf("mctl %v: error = %v", args, err)
		}
	}
}

// Cada comando aparece una sola vez en la tabla y todos se encuentran por su nombre.
func TestAreasTable(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range areas {
		for _, c := range a.Commands {
			if seen[c.Name] {
				t.Errorf("comando repetido: %q", c.Name)
			}
			seen[c.Name] = true
			if _, _, ok := cli.Find(areas, strings.Fields(c.Name)); !ok {
				t.Errorf("no se encuentra %q", c.Name)
			}
		}
	}
	if len(seen) < 70 {
		t.Errorf("faltan comandos: %d", len(seen))
	}
}

// Con la bandera de idioma delante, --help, -h, help y --version siguen siendo ayuda y versión, no un error de uso.
func TestAyudaConLang(t *testing.T) {
	want, _ := os.ReadFile("testdata/help.golden")
	for _, pre := range [][]string{{"--lang", "en"}, {"--lang=es"}, {"--no-color", "--lang", "en"}} {
		for _, arg := range []string{"--help", "-h", "help"} {
			if out := must(t, "", append(append([]string{}, pre...), arg)...); out != string(want) {
				t.Errorf("mctl %v %s: no mostró la ayuda:\n%s", pre, arg, out)
			}
		}
		if out := must(t, "", append(append([]string{}, pre...), "--version")...); out != must(t, "", "--version") {
			t.Errorf("mctl %v --version: %q", pre, out)
		}
	}
}
