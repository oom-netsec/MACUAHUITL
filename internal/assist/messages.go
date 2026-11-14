package assist

import (
	"errors"
	"fmt"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Los textos que el motor le devuelve al ingeniero (errores de armado, negativas, avisos) viven en el catálogo
// (i18n/catalog_assist.go): aquí solo se arman con su código y sus argumentos. Con es salen byte por byte como antes.

// cerr es un error con código del catálogo; los argumentos van en pares nombre, valor.
func cerr(code string, kv ...any) error { return i18n.New(code, i18n.A(kv...)) }

// note arma un aviso del plan: el texto en es y su clave con argumentos.
func note(code string, kv ...any) i18n.Text { return i18n.Tx(code, kv...) }

// codedRefusal es una negativa con su centinela (ErrPortRefused, ErrRotateRefused o ErrRestoreRefused): Error() es el texto
// en es de siempre (centinela + ": " + motivo); Localize da el mismo en el idioma pedido.
type codedRefusal struct {
	base error
	code string    // assist.port_refused, assist.rotate_refused o assist.restore_refused
	why  i18n.Text // el motivo concreto
}

func newRefusal(base error, code string, why i18n.Text) error { return &codedRefusal{base, code, why} }

func (e *codedRefusal) Error() string               { return e.Localize(i18n.Es) }
func (e *codedRefusal) Is(target error) bool        { return target == e.base }
func (e *codedRefusal) Reason() string              { return e.code }
func (e *codedRefusal) Metadata() map[string]string { return i18n.Metadata(e.code, nil) }
func (e *codedRefusal) Localize(loc string) string {
	return i18n.Msg(loc, e.code, i18n.A("detail", e.why.In(loc)))
}

// refusalOf es la negativa del puerto como negativa de snippet (mismo motivo, con su traducción).
func refusalOf(err error) error {
	var cr *codedRefusal
	if errors.As(err, &cr) {
		return &SnippetRefusal{Detail: cr.why.In(i18n.Es), Why: cr.why}
	}
	return refuseSnippet("assist.refused.raw", "detail", err.Error())
}

// prefixed antepone el código (con {detail}) al texto de err, en el idioma que se pida. Tiene su propio motivo y metadata (la del código),
// no los del error de dentro: el valor no cumple una regla de armado, no la validación de campos de assist.invalid_value.
type prefixed struct {
	code  string
	inner error
}

func withPrefix(code string, inner error) error { return &prefixed{code, inner} }

func (e *prefixed) Unwrap() error { return e.inner }
func (e *prefixed) Error() string { return e.Localize(i18n.Es) }
func (e *prefixed) Localize(loc string) string {
	d := e.inner.Error()
	var c i18n.Coded
	if errors.As(e.inner, &c) {
		d = c.Localize(loc)
	}
	return i18n.Msg(loc, e.code, i18n.A("detail", d))
}
func (e *prefixed) Reason() string              { return i18n.Reason(e.code) }
func (e *prefixed) Metadata() map[string]string { return i18n.Metadata(e.code, nil) }

// litErr es un error interno del plan (línea inválida, reversa que no cuadra) con su texto en los dos idiomas. Error() es el de es de siempre;
// los argumentos que son errores se escriben en el idioma pedido. Los textos van como frases enteras (no se arman por piezas) y las líneas de
// configuración y los comandos que citan no se traducen.
type litErr struct {
	es, en string
	args   []any
}

func lerr(es, en string, a ...any) error { return &litErr{es, en, a} }

func (e *litErr) Error() string { return e.Localize(i18n.Es) }
func (e *litErr) Localize(loc string) string {
	args := make([]any, len(e.args))
	for i, a := range e.args {
		if err, ok := a.(error); ok {
			a = errIn(loc, err)
		}
		args[i] = a
	}
	f := e.es
	if loc == i18n.En {
		f = e.en
	}
	return fmt.Sprintf(f, args...)
}

// errIn es err en el idioma pedido: un litErr o un error con código sale en ese idioma, cualquier otro es err.Error().
func errIn(loc string, err error) string {
	var c i18n.Coded
	if errors.As(err, &c) {
		return i18n.In(loc, err)
	}
	var l interface{ Localize(string) string }
	if errors.As(err, &l) {
		return l.Localize(loc)
	}
	return err.Error()
}

// errText es el texto de err en los dos idiomas, ya resuelto.
func errText(err error) i18n.Text { return i18n.Lit(errIn(i18n.Es, err), errIn(i18n.En, err)) }

// lt es un texto en los dos idiomas con sus argumentos (un motivo de la restauración por diff).
func lt(es, en string, a ...any) i18n.Text {
	if len(a) == 0 {
		return i18n.Lit(es, en)
	}
	return i18n.Lit(fmt.Sprintf(es, a...), fmt.Sprintf(en, a...))
}

// planError es el rechazo de Validate: las piezas se arman en el idioma pedido y se les quitan los secretos al final de cada una.
type planError struct {
	bad     []func(loc string) string
	secrets []string
	generic bool
}

func (e *planError) Is(target error) bool { return target == ErrInvalidPlan }
func (e *planError) Error() string        { return e.Localize(i18n.Es) }
func (e *planError) Reason() string       { return i18n.Reason("assist.invalid_plan") }
func (e *planError) Metadata() map[string]string {
	return i18n.Metadata("assist.invalid_plan", nil)
}
func (e *planError) Localize(loc string) string {
	parts := make([]string, len(e.bad))
	for i, f := range e.bad {
		parts[i] = f(loc)
	}
	scrub := Scrub
	if loc == i18n.En {
		scrub = scrubEN
	}
	return i18n.Msg(loc, "assist.invalid_plan", i18n.A("detail", scrub(strings.Join(parts, "; "), e.secrets, e.generic)))
}

// sentinel es un error con código del catálogo que sigue reconociéndose como su centinela (errors.Is).
type sentinel struct {
	base error
	c    *i18n.Error
}

func (e sentinel) Is(target error) bool        { return target == e.base }
func (e sentinel) Error() string               { return e.c.Error() }
func (e sentinel) Reason() string              { return e.c.Reason() }
func (e sentinel) Metadata() map[string]string { return e.c.Metadata() }
func (e sentinel) Localize(loc string) string  { return e.c.Localize(loc) }

// whyErr es el rechazo de Check por una línea que la lista cerrada no admite, con su motivo en los dos idiomas.
type whyErr struct {
	line, path string
	why        i18n.Text
}

func (e *whyErr) Error() string { return e.Localize(i18n.Es) }
func (e *whyErr) Localize(loc string) string {
	if loc == i18n.En {
		return fmt.Sprintf("%q (in %q): %s", e.line, e.path, e.why.In(loc))
	}
	return fmt.Sprintf("%q (en %q): %s", e.line, e.path, e.why.In(loc))
}
