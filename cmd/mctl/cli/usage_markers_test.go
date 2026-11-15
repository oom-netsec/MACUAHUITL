package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Marcadores en mayúsculas que pueden quedar en un uso en inglés: siglas y términos técnicos. Cualquier otro es
// español sin traducir: se agrega a placeholderWord.
var marcadoresEn = map[string]bool{
	"JSON": true, "HOST": true, "HOSTS": true, "VLAN": true, "SHA": true, "ITEM": true, "URL": true, "OID": true, "CERT": true,
	"AES": true, "WILDCARD": true, "LOCAL": true, "SPDX": true, "ID_A": true, "ID_B": true, "SCRIPT_ID": true, "DIR": true,
	"HEX": true, "BYTES": true, "CSR": true, "MAC": true, "SSH": true, "SSID": true, "NAS": true, "DNS": true, "TFTP": true,
	"UDP": true, "TCP": true, "ID": true, "PEM": true, "CSV": true, "YAML": true, "RUN": true, "MIN-MAX": true, "TS": true, "IP": true, "IF": true, "CA": true,
}

// Cada «uso: mctl …» de cmd/mctl (y el uso que recibe fleetCmd), pasado por LocalizeUsage, no trae marcadores en
// español.
func TestUsosEnInglesSinMarcadoresEnEspanol(t *testing.T) {
	t.Cleanup(func() { SetLang("") })
	SetLang("")
	var usos []string
	fset := token.NewFileSet()
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BasicLit:
				if s, err := strconv.Unquote(x.Value); err == nil && x.Kind == token.STRING && strings.Contains(s, "uso: mctl") {
					usos = append(usos, s)
				}
			case *ast.CallExpr:
				if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "fleetCmd" && len(x.Args) > 2 {
					if l, ok := x.Args[2].(*ast.BasicLit); ok {
						if s, err := strconv.Unquote(l.Value); err == nil {
							usos = append(usos, "uso: mctl "+s)
						}
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil || len(usos) < 50 {
		t.Fatalf("usos encontrados: %d, err %v", len(usos), err)
	}
	for _, s := range usos {
		got := LocalizeUsage(errorString(s)).Error()
		if strings.Contains(got, "uso: mctl") || strings.Contains(got, "clave=valor") {
			t.Errorf("sin traducir: %s", got)
		}
		for _, w := range upperWord.FindAllString(got, -1) {
			w = strings.TrimRight(w, "-")
			if !marcadoresEn[w] && !isEnglish(w) {
				t.Errorf("marcador %q sin traducir en: %s", w, got)
			}
		}
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }

// isEnglish: los destinos de placeholderWord son inglés por construcción.
func isEnglish(w string) bool {
	for _, v := range placeholderWord {
		if v == w {
			return true
		}
	}
	return strings.HasPrefix(w, "HIGH-") || strings.HasPrefix(w, "LISTEN-")
}
