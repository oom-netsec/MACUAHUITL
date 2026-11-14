package main

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
)

// La ayuda es contrato: testdata/help.golden (inglés, el canónico) y help_es.golden (--lang es) son el texto de --help
// (con salto final).
func TestHelpGolden(t *testing.T) {
	for _, c := range []struct {
		file string
		pre  []string
	}{{"testdata/help.golden", nil}, {"testdata/help_es.golden", []string{"--lang", "es"}}} {
		want, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		for _, arg := range []string{"--help", "-h", "help"} {
			if out := mustRaw(t, "", append(append([]string{}, c.pre...), arg)...); out != string(want) {
				t.Fatalf("mctl %v %s: la ayuda cambió:\n%s", c.pre, arg, out)
			}
		}
		// Sin comando, con comando desconocido o incompleto: el mismo texto como error, sin salto final.
		for _, args := range [][]string{nil, {"--no-color"}, {"frob", "x"}, {"vault"}, {"vault", "frob"}} {
			t.Setenv("XDG_RUNTIME_DIR", "")
			_, err := mctlRaw(t, "", append(append([]string{}, c.pre...), args...)...)
			if len(c.pre) > 0 && len(args) == 0 {
				continue // «--lang es» solo (sin comando) cae en el mismo texto, pero no es el caso que se vigila
			}
			if err == nil || err.Error() != strings.TrimSuffix(string(want), "\n") {
				t.Fatalf("mctl %v %v: error = %v", c.pre, args, err)
			}
		}
	}
}

// La ayuda en inglés y la de --lang es dicen lo mismo línea por línea: el mismo comando (sus primeras palabras) y las
// mismas banderas --x; solo cambia la prosa.
func TestHelpMismasLineas(t *testing.T) {
	en, _ := os.ReadFile("testdata/help.golden")
	es, _ := os.ReadFile("testdata/help_es.golden")
	le, ls := strings.Split(string(en), "\n"), strings.Split(string(es), "\n")
	if len(le) != len(ls) {
		t.Fatalf("en tiene %d líneas y es %d", len(le), len(ls))
	}
	flag := regexp.MustCompile(`--[a-z][a-z0-9-]*`)
	word := regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	for i := range le {
		if a, b := flag.FindAllString(le[i], -1), flag.FindAllString(ls[i], -1); !slices.Equal(a, b) {
			t.Errorf("línea %d: banderas distintas %v / %v\n  en: %s\n  es: %s", i+1, a, b, le[i], ls[i])
		}
		if i == 0 || !strings.HasPrefix(le[i], "  ") || strings.HasPrefix(strings.TrimSpace(le[i]), "(") || strings.HasPrefix(le[i], "   ") {
			continue // el encabezado y la prosa de continuación no son una línea de comando
		}
		fe, fs := strings.Fields(le[i]), strings.Fields(ls[i])
		for k := 0; k < 2 && k < len(fe) && k < len(fs); k++ {
			if (word.MatchString(fe[k]) || word.MatchString(fs[k])) && fe[k] != fs[k] {
				t.Errorf("línea %d: comando distinto %q / %q\n  en: %s\n  es: %s", i+1, fe[k], fs[k], le[i], ls[i])
			}
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
	en, _ := os.ReadFile("testdata/help.golden")
	es, _ := os.ReadFile("testdata/help_es.golden")
	for _, pre := range [][]string{{"--lang", "en"}, {"--lang=es"}, {"--no-color", "--lang", "en"}, {"--no-color", "--lang=es"}} {
		want := en
		if strings.Contains(strings.Join(pre, " "), "es") {
			want = es
		}
		for _, arg := range []string{"--help", "-h", "help"} {
			if out := mustRaw(t, "", append(append([]string{}, pre...), arg)...); out != string(want) {
				t.Errorf("mctl %v %s: no mostró la ayuda:\n%s", pre, arg, out)
			}
		}
		if out := must(t, "", append(append([]string{}, pre...), "--version")...); out != must(t, "", "--version") {
			t.Errorf("mctl %v --version: %q", pre, out)
		}
	}
}
