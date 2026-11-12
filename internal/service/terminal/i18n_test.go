package terminal

import (
	"context"
	"strings"
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// terminalCasos abre la terminal con peticiones que se rechazan antes de conectar; ctx fija el idioma.
func terminalCasos(t *testing.T, ctx context.Context) map[string]string {
	t.Helper()
	out := map[string]string{}
	ask := func(n string, r *rig, open *v1.TerminalOpen) {
		st := newStream(ctx)
		if open == nil {
			st.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Data{Data: []byte("x")}}
		} else {
			st.in <- &v1.OpenTerminalRequest{Msg: &v1.OpenTerminalRequest_Open{Open: open}}
		}
		err := r.svc.OpenTerminal(st)
		out[n] = "ok"
		if err != nil {
			out[n] = "ERROR: " + err.Error()
		}
	}
	r := newRig(t, simulator.Config{})
	ask("no_abre", r, nil)
	ask("sin_equipo", r, &v1.TerminalOpen{})
	ask("puerto", r, &v1.TerminalOpen{Address: "192.0.2.1", CredentialId: "x", Port: 70000})
	ask("guard", r, &v1.TerminalOpen{Name: "X", Address: "10.0.0.1/8", Port: 22, CredentialId: r.open.CredentialId})
	r.svc.live.Store(maxSessions)
	ask("limite", r, r.open)
	r.svc.live.Store(0)
	r.d.V.LockAll()
	ask("boveda", r, r.open)
	_ = servicetest.New
	return out
}

func TestTerminalRegresionEs(t *testing.T) {
	base := terminalCasos(t, context.Background())
	i18ntest.Golden(t, "testdata/terminal_es.golden.json", base)
	for _, loc := range []string{"es", "es-MX", "fr"} {
		for k, v := range terminalCasos(t, i18n.WithLocale(context.Background(), loc)) {
			if base[k] != v {
				t.Errorf("%s con %q difiere de sin idioma", k, loc)
			}
		}
	}
}

func TestTerminalEnSinEspanol(t *testing.T) {
	for k, v := range terminalCasos(t, i18n.WithLocale(context.Background(), "en")) {
		if k == "guard" { // el texto sale de internal/transport (fuera del bloque D)
			continue
		}
		if strings.ContainsAny(v, "áéíóúñ¿") || strings.Contains(v, "indica") || strings.Contains(v, "máximo") {
			t.Errorf("%s: queda español: %q", k, v)
		}
	}
}
