package transport

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestErroresGuardEsYEn(t *testing.T) {
	g := NewGuard(func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }, nil)
	ctx := context.Background()
	_, e1 := g.lookup(ctx, "")
	_, e2 := g.lookup(ctx, "x.lab")
	e3 := g.Allow(ctx, "j", []string{"10.0.0.1/8"})
	_, e4 := g.DialNetwork(ctx, "j", "sctp", "10.0.0.1", 1)
	for i, w := range []struct {
		err    error
		es, en string
	}{
		{e1, "transport: dirección vacía", "transport: empty address"},
		{e2, `transport: resolver "x.lab": no such host`, `transport: resolving "x.lab": no such host`},
		{e3, "transport: 10.0.0.1/8 tiene bits de host; ¿quisiste decir 10.0.0.0/8?", "transport: 10.0.0.1/8 has host bits; did you mean 10.0.0.0/8?"},
		{e4, `transport: red "sctp" no soportada`, `transport: network "sctp" not supported`},
	} {
		if w.err == nil || w.err.Error() != w.es || i18n.In("en", w.err) != w.en {
			t.Errorf("%d: es %q en %q, quería %q / %q", i, w.err, i18n.In("en", w.err), w.es, w.en)
		}
	}
}
