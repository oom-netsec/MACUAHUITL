package i18n

import (
	"context"
	"errors"
	"fmt"
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

func TestRenderPlural(t *testing.T) {
	for n, want := range map[string]string{"1": "1 equipo", "0": "0 equipos", "3": "3 equipos"} {
		if got := render("{n} {n|equipo|equipos}", Args{"n": n}); got != want {
			t.Errorf("n=%s: %q", n, got)
		}
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
		"fr, en;q=0.8": En, "en, es": En, "es, en": Es, "en;q=0.5, es;q=0.9": Es, "en;q=0": Es, "de, fr;q=0.9, en;q=0.1": En, "*": Es, "en;q=x": Es, "en;q=NaN": Es, "en;q=2": Es, "en;foo=1;q=0.3, es;q=0.2": En, "en;foo=1;q=0": Es, "en;q=0.5;x=1, es;q=0.4": En,
	} {
		if got := Parse(in); got != want {
			t.Errorf("Parse(%q)=%q want %q", in, got, want)
		}
	}
}

func TestParseCortaElHeader(t *testing.T) {
	// El header se corta a 256 bytes: un en que queda después del corte no cuenta.
	if got := Parse(strings.Repeat(" ", 300) + "en"); got != Es {
		t.Fatalf("%q", got)
	}
	// El corte deja «en» sin su «;q=0.1»: la entrada incompleta se descarta en vez de valer q=1.
	h := "es;q=0.5," + strings.Repeat(" ", 245) + "en;q=0.1"
	if got := Parse(h); got != Es {
		t.Fatalf("entrada cortada: %q", got)
	}
	if got := Parse(strings.Repeat("x,", 100) + "en"); got != En {
		t.Fatalf("antes del corte debe contar: %q", got)
	} // El corte cae justo antes de una coma: el último trozo está entero y cuenta.
	h = strings.Repeat(" ", 254) + "en" + ",es;q=0.1"
	if got := Parse(h); got != En {
		t.Fatalf("trozo entero antes de la coma: %q", got)
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
	re := regexp.MustCompile(`\{([a-z_0-9]+)(?::q|\|[^}]*)?\}`)
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
		// Una plantilla puede omitir un argumento (la etiqueta en español no se repite en inglés), pero nunca usar uno
		// no declarado, y todo declarado debe usarse en alguna de las dos.
		es, en := holders(e.Es), holders(e.En)
		union := slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(es), en...))))
		if !slices.Equal(union, want) {
			t.Errorf("%s: es usa %v, en usa %v y declara %v", code, es, en, want)
		}
		for _, x := range e.Extra {
			if slices.Contains(e.Args, x) {
				t.Errorf("%s: %s está en Args y en Extra", code, x)
			}
		}
	}
}

func TestEnglishFijaElIdiomaYConservaElEnvoltorio(t *testing.T) {
	e := New("ingest.invalid.addr.any", nil)
	if got, want := English(e), e.Localize(En); got != want || got == e.Error() {
		t.Fatalf("got %q want %q (es %q)", got, want, e.Error())
	}
	w := fmt.Errorf("syslog: %w", e)
	if got, want := English(w), "syslog: "+e.Localize(En); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := English(errors.New("sin código")); got != "sin código" {
		t.Fatalf("got %q", got)
	}
	if got := English(nil); got != "" {
		t.Fatalf("nil: %q", got)
	}
}

// Un argumento que es un código de valor (calc.val.*, ike.val.*) se escribe en el idioma pedido; varios separados
// por coma se unen con «, »; lo que no es un código del catálogo queda tal cual.
func TestValoresComoArgumentos(t *testing.T) {
	for _, c := range []struct{ loc, key, arg, want string }{
		{Es, "ike.finding.p1_propuesta.explanation_attrs", "ike.val.attr.encryption,ike.val.attr.dh_group", "cifrado, grupo DH"},
		{En, "ike.finding.p1_propuesta.explanation_attrs", "ike.val.attr.encryption,ike.val.attr.dh_group", "encryption, DH group"},
		{En, "ike.finding.p1_propuesta.explanation_attrs", "ike.val.attr.hash", "hash"},
		{En, "ike.finding.p1_propuesta.explanation_attrs", "ike.val.attr.hash,no-es-clave", "ike.val.attr.hash,no-es-clave"},
		{En, "ike.finding.p1_propuesta.explanation_attrs", "ike.val.nada", "ike.val.nada"},
	} {
		if got := Msg(c.loc, c.key, A("attrs", c.arg)); !strings.HasSuffix(got, c.want+".") {
			t.Errorf("%s %q: %q no termina en %q", c.loc, c.arg, got, c.want)
		}
	}
}

// Solo se resuelven los argumentos que la entrada declara en Refs: un dato que coincide con una clave sale literal.
func TestDatosQueSeParecenAClavesSalenLiterales(t *testing.T) {
	for _, loc := range []string{Es, En} {
		if got := Msg(loc, "ike.text.proposal", A("phase", 1, "source", "s", "detail", "calc.val.yes")); !strings.HasSuffix(got, ": calc.val.yes") {
			t.Errorf("%s: %q", loc, got)
		}
		if got := Msg(loc, "tls.finding.name_mismatch", A("name", "ike.val.result.rejected", "san", "calc.val.yes")); !strings.Contains(got, `"ike.val.result.rejected"`) || !strings.HasSuffix(got, "calc.val.yes)") {
			t.Errorf("%s: %q", loc, got)
		}
		if got := Msg(loc, "dns.finding.no_ptr", A("ip", "ike.val.attr.hash,calc.val.no")); got != Msg(loc, "dns.finding.no_ptr", A("ip", "ike.val.attr.hash,calc.val.no")) || !strings.Contains(got, "ike.val.attr.hash,calc.val.no") {
			t.Errorf("%s: %q", loc, got)
		}
		// el arg declarado sí se resuelve, también una lista
		if got := Msg(loc, "ike.text.result", A("result", "ike.val.result.rejected,ike.val.attr.hash")); strings.Contains(got, "ike.val.") {
			t.Errorf("%s: %q", loc, got)
		}
		// y un valor declarado que no es clave queda literal
		if got := Msg(loc, "ike.text.result", A("result", "calc.val.nada")); !strings.Contains(got, "calc.val.nada") {
			t.Errorf("%s: %q", loc, got)
		}
	}
}

// RFC 4291: el alcance 4 de multicast IPv6 es admin-local.
func TestAlcanceMulticastAdminLocal(t *testing.T) {
	if got := Msg(En, "calc.val.kind.mcast6_4", nil); got != "multicast, admin-local scope" {
		t.Errorf("%q", got)
	}
}

// In traduce el tramo con código y conserva el envoltorio; con es, o sin código, es el mensaje de siempre.
func TestInTraduceElTramoConCodigoYConservaElEnvoltorio(t *testing.T) {
	e := New("file.exists", nil)
	w := fmt.Errorf("guardar: %w", e)
	if got := In(En, w); got != "guardar: the file already exists" {
		t.Fatalf("en: %q", got)
	}
	for _, loc := range []string{Es, "fr", ""} {
		if got := In(loc, w); got != w.Error() {
			t.Fatalf("%q: %q", loc, got)
		}
	}
	if In(En, errors.New("boom")) != "boom" || In(En, nil) != "" {
		t.Fatal("sin código o nil")
	}
}

// Wrap conserva la causa para errors.Is y la da en el idioma pedido; con es el texto es el de siempre.
func TestWrapConservaLaCausaYLaTraduce(t *testing.T) {
	cause := New("file.exists", nil)
	w := Wrap("patrol.err.credential", cause, nil)
	if !errors.Is(w, cause) {
		t.Fatal("errors.Is no ve la causa")
	}
	if got := w.Error(); got != "patrol: credencial: el archivo ya existe" {
		t.Fatalf("es: %q", got)
	}
	if got := In(En, fmt.Errorf("x: %w", w)); got != "x: patrol: credential: the file already exists" {
		t.Fatalf("en: %q", got)
	}
}
