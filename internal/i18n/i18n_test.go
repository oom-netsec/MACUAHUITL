package i18n

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestRenderEscapesYVerbo(t *testing.T) {
	got := render("lleva {{fecha}} y {x} y {y:q}", Args{"x": "1", "y": "a\"b"})
	if want := `lleva {fecha} y 1 y "a\"b"`; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestTIdioma(t *testing.T) {
	add(map[string]entry{"prueba.uno": {Es: "hola {n}", En: "hello {n}", Args: []string{"n"}}})
	defer delete(catalog, "prueba.uno")
	ctx := context.Background()
	if got := T(ctx, "prueba.uno", A("n", 3)); got != "hola 3" {
		t.Fatalf("sin locale debe ser es: %q", got)
	}
	if got := T(WithLocale(ctx, En), "prueba.uno", A("n", 3)); got != "hello 3" {
		t.Fatalf("en: %q", got)
	}
	if got := T(ctx, "no.existe", nil); got != "no.existe" {
		t.Fatalf("código desconocido: %q", got)
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string]string{
		"": Es, "es": Es, "en": En, "es-MX": Es, "en-US": En, "EN-gb": En, "fr": Es, "xx-yy": Es,
		"fr, en;q=0.8": En, "en, es": En, "es, en": Es, "en;q=0.5, es;q=0.9": Es, "en;q=0": Es, "de, fr;q=0.9, en;q=0.1": En, "*": Es, "en;q=x": En,
	} {
		if got := Parse(in); got != want {
			t.Errorf("Parse(%q)=%q want %q", in, got, want)
		}
	}
}

func TestErrorMetadataSoloDeclarados(t *testing.T) {
	add(map[string]entry{"prueba.meta": {Reason: "prueba.r", Es: "a {n}", En: "b {n}", Args: []string{"n"}, Extra: []string{"path"}, Meta: map[string]string{"field": "f"}}})
	defer delete(catalog, "prueba.meta")
	e := New("prueba.meta", A("n", 1, "path", "/x", "secreto", "hunter2"))
	if e.Reason() != "prueba.r" {
		t.Fatal(e.Reason())
	}
	m := e.Metadata()
	if m["n"] != "1" || m["path"] != "/x" || m["field"] != "f" || len(m) != 3 {
		t.Fatalf("metadata: %v", m)
	}
	var c Coded
	if !errors.As(errors.Join(errors.New("x"), e), &c) {
		t.Fatal("errors.As debe hallar el error con código")
	}
}

// Cobertura: todo código lleva es y en, con los mismos argumentos, y ninguno sobra ni falta en la plantilla.
func TestCatalogoCobertura(t *testing.T) {
	re := regexp.MustCompile(`\{([a-z_0-9]+)(?::q)?\}`)
	holders := func(s string) []string {
		s = strings.NewReplacer("{{", "", "}}", "").Replace(s)
		var out []string
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			if !slices.Contains(out, m[1]) {
				out = append(out, m[1])
			}
		}
		slices.Sort(out)
		return out
	}
	for code, e := range catalog {
		if e.Es == "" || e.En == "" {
			t.Errorf("%s: falta es o en", code)
		}
		want := slices.Clone(e.Args)
		slices.Sort(want)
		if got := holders(e.Es); !slices.Equal(got, want) {
			t.Errorf("%s: es usa %v y declara %v", code, got, want)
		}
		if got := holders(e.En); !slices.Equal(got, want) {
			t.Errorf("%s: en usa %v y declara %v", code, got, want)
		}
		for _, x := range e.Extra {
			if slices.Contains(e.Args, x) {
				t.Errorf("%s: %s está en Args y en Extra", code, x)
			}
		}
	}
}
