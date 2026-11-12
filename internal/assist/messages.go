package assist

import (
	"errors"

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

// raw es un motivo que aún no tiene su código: sale tal cual en los dos idiomas.
func raw(code, detail string) i18n.Text { return i18n.Tx(code+".raw", "detail", detail) }

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
