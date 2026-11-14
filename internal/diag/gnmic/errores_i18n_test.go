package gnmic

import (
	"context"
	"errors"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestErroresGNMIEsEn(t *testing.T) {
	ctx := context.Background()
	_, e1 := ParsePath("")
	_, e2 := ParsePath("/a[k")
	_, e3 := ParsePath("/a]")
	_, e4 := Get(ctx, nil, Target{}, []string{"/a"}, "x")
	e5 := Subscribe(ctx, nil, Target{}, []string{"/a"}, "raro", 0, nil)
	_, e6 := Get(ctx, nil, Target{}, nil, "")
	for _, c := range []struct {
		err    error
		es, en string
	}{
		{e1, "gnmi: parámetros inválidos: ruta vacía", "gnmi: invalid parameters: empty path"},
		{e2, `gnmi: parámetros inválidos: falta ] en "/a[k"`, `gnmi: invalid parameters: missing ] in "/a[k"`},
		{e3, `gnmi: parámetros inválidos: ] sin [ en "/a]"`, `gnmi: invalid parameters: ] without [ in "/a]"`},
		{e4, `gnmi: parámetros inválidos: codificación "x" desconocida`, `gnmi: invalid parameters: unknown encoding "x"`},
		{e5, `gnmi: parámetros inválidos: modo "raro" desconocido (sample u on_change)`, `gnmi: invalid parameters: unknown mode "raro" (sample or on_change)`},
		{e6, "gnmi: parámetros inválidos: sin rutas", "gnmi: invalid parameters: no paths"},
	} {
		if !errors.Is(c.err, ErrInvalid) || c.err.Error() != c.es || i18n.English(c.err) != c.en {
			t.Errorf("es=%q en=%q", c.err, i18n.English(c.err))
		}
	}
}
