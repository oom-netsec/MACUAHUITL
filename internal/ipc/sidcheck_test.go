package ipc

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func TestSameSID(t *testing.T) {
	const me = "S-1-5-21-111-222-333-1001"
	for _, c := range []struct {
		name      string
		peer, own string
		want      bool
	}{
		{"igual", me, me, true},
		{"minúsculas", "s-1-5-21-111-222-333-1001", me, true},
		{"otro usuario", "S-1-5-21-111-222-333-1002", me, false},
		{"prefijo no es igual", "S-1-5-21-111-222-333-100", me, false},
		{"SYSTEM", "S-1-5-18", me, false},
		{"peer vacío falla cerrado", "", me, false},
		{"propio vacío falla cerrado", "", "", false},
		{"solo propio vacío", me, "", false},
	} {
		if got := sameSID(c.peer, c.own); got != c.want {
			t.Errorf("%s: sameSID(%q, %q) = %v, quería %v", c.name, c.peer, c.own, got, c.want)
		}
	}
}

// El mensaje de «el canal lo tiene otro usuario» (ipc_windows.go) existe en los dos idiomas.
func TestMensajePipeDeOtroUsuario(t *testing.T) {
	for _, loc := range []string{"es", "en"} {
		if m := i18n.Msg(loc, "ipc.err.pipe_other_user", nil); m == "" || m == "ipc.err.pipe_other_user" {
			t.Errorf("%s: sin texto (%q)", loc, m)
		}
	}
}
