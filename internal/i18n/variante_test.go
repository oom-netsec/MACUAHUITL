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
	for _, c := range Codes() {
		if c == "prueba.variante.windows" {
			t.Fatal("Codes no debe listar las variantes .windows")
		}
	}
}

// Una variante «.windows» reemplaza a un código que existe y solo usa argumentos de él.
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
		// El llamador pasa los argumentos de la base: la variante puede usar menos (p. ej. sin setcap en Windows), nunca otros.
		if !subset(e.Args, b.Args) || !sameArgs(b.Refs, e.Refs) {
			t.Errorf("%s: argumentos %v (deben estar en los de %s %v) o refs %v distintos de %v", code, e.Args, base, b.Args, e.Refs, b.Refs)
		}
		// Reason, Meta y Extra viajan por la base (Reason/Metadata): en la variante se ignorarían sin aviso.
		if e.Reason != "" || len(e.Meta) > 0 || len(e.Extra) > 0 {
			t.Errorf("%s: una variante solo cambia el texto (sin Reason, Meta ni Extra)", code)
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

func subset(a, b []string) bool {
	in := map[string]bool{}
	for _, x := range b {
		in[x] = true
	}
	for _, x := range a {
		if !in[x] {
			return false
		}
	}
	return true
}
