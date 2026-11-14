package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
)

var (
	// Palabras españolas comunes que no pueden quedar en un «usage: mctl …» en inglés (las banderas --x y los valores
	// técnicos como renombrar|reemplazar|omitir no cuentan).
	palabraEs = regexp.MustCompile(`(?i)\b(todas?|todos|también|archivo|carpeta|para|con|sin|cada|uno|equipo|puerto|ruta|nombre|valor|una|los|las|del|que|según|opcional)\b`)
	acentoEs  = regexp.MustCompile(`[áéíóúñ¿¡]`)
	banderaEs = regexp.MustCompile(`--[a-zA-Z0-9-]+(=\S*)?`)
)

// Recorre todos los «uso: mctl …» de los fuentes de mctl: con en, ninguno deja español.
func TestUsosEnInglesSinEspanol(t *testing.T) {
	t.Cleanup(func() { cli.SetLang("") })
	cli.SetLang("en")
	n := 0
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(x ast.Node) bool {
			lit, ok := x.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil || !strings.Contains(s, "uso: mctl") {
				return true
			}
			n++
			got := cli.LocalizeUsage(errString(s)).Error()
			plain := banderaEs.ReplaceAllString(got, "")
			if !strings.HasPrefix(got, "usage: mctl") && !strings.Contains(got, "usage: mctl") {
				t.Errorf("%s: %q no pasó a «usage: mctl»", p, got)
			}
			if w := palabraEs.FindString(plain); w != "" || acentoEs.MatchString(plain) {
				t.Errorf("%s: con en queda español (%q) en %q", p, w, got)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 30 {
		t.Fatalf("solo se encontraron %d usos: ¿cambió el recorrido?", n)
	}
}

type errString string

func (e errString) Error() string { return string(e) }
