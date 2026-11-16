package i18n

import "testing"

// En Windows, «<código>.windows» reemplaza al código si existe (textos que nombran algo de Linux), como en la UI.
func TestMsgVarianteWindows(t *testing.T) {
	add(map[string]entry{
		"prueba.variante":         {Es: "en Linux {x}", En: "on Linux {x}", Args: []string{"x"}},
		"prueba.variante.windows": {Es: "en Windows {x}", En: "on Windows {x}", Args: []string{"x"}},
		"prueba.sola":             {Es: "igual", En: "same"},
	})
	defer func() {
		delete(catalog, "prueba.variante")
		delete(catalog, "prueba.variante.windows")
		delete(catalog, "prueba.sola")
	}()
	prev := goos
	defer func() { goos = prev }()

	goos = "linux"
	if got := Msg(En, "prueba.variante", A("x", 1)); got != "on Linux 1" {
		t.Fatalf("linux: %q", got)
	}
	goos = "windows"
	if got := Msg(Es, "prueba.variante", A("x", 1)); got != "en Windows 1" {
		t.Fatalf("windows: %q", got)
	}
	if got := Msg(En, "prueba.sola", nil); got != "same" {
		t.Fatalf("sin variante: %q", got)
	}
}

// Una variante «.windows» reemplaza a un código que existe y lleva sus mismos argumentos.
func TestVariantesWindowsTienenBase(t *testing.T) {
	for code, e := range catalog {
		base, ok := cutSuffix(code, ".windows")
		if !ok {
			continue
		}
		b, exists := catalog[base]
		if !exists {
			t.Errorf("%s sin código base", code)
			continue
		}
		if !sameArgs(b.Args, e.Args) {
			t.Errorf("%s: argumentos %v distintos de %s %v", code, e.Args, base, b.Args)
		}
	}
}

func cutSuffix(s, suf string) (string, bool) {
	if len(s) > len(suf) && s[len(s)-len(suf):] == suf {
		return s[:len(s)-len(suf)], true
	}
	return "", false
}

func sameArgs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]bool{}
	for _, x := range a {
		seen[x] = true
	}
	for _, x := range b {
		if !seen[x] {
			return false
		}
	}
	return true
}
