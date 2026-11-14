package packtest

import (
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// packtest trae una llave de pruebas conocida: ningún código de producción puede importarlo, o un paquete firmado con ella
// pasaría por oficial.
func TestSoloLasPruebasImportanPacktest(t *testing.T) {
	const imp = "github.com/oom-netsec/MACUAHUITL/internal/pack/packtest"
	root := RepoDir()
	n := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) {
			return nil // un temporal de otra prueba que corre a la vez (p. ej. cmd/mctl/salidas-…) desapareció a mitad del recorrido
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", ".worktrees", "dist", "bin", "outputs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return nil // un .go que no compila no es asunto de esta prueba
		}
		n++
		for _, i := range f.Imports {
			if strings.Trim(i.Path.Value, `"`) == imp {
				t.Errorf("%s importa packtest y no es una prueba", p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 100 {
		t.Fatalf("solo se revisaron %d archivos: ¿RepoDir está bien?", n)
	}
}
