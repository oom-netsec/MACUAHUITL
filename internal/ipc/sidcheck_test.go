package ipc

import (
	"errors"
	"strings"
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

func TestCheckServer(t *testing.T) {
	const me, other = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	for _, c := range []struct {
		name            string
		owner, sid, own string
		ok              bool
	}{
		{"bueno", me, me, me, true},
		{"dueño ajeno", other, me, me, false},
		{"SID del proceso ajeno", me, other, me, false},
		{"los dos ajenos", other, other, me, false},
		{"dueño vacío", "", me, me, false},
		{"SID vacío", me, "", me, false},
		{"propio vacío", me, me, "", false},
	} {
		if err := checkServer(c.owner, c.sid, c.own); (err == nil) != c.ok {
			t.Errorf("%s: checkServer = %v, quería ok=%v", c.name, err, c.ok)
		}
	}
}

func TestServerTrusted(t *testing.T) {
	const medio, bajo, alto = 0x2000, 0x1000, 0x3000
	cliente := tokenFacts{IL: medio}
	for _, c := range []struct {
		name   string
		server tokenFacts
		client tokenFacts
		ok     bool
	}{
		{"igual", tokenFacts{IL: medio}, cliente, true},
		{"mayor", tokenFacts{IL: alto}, cliente, true},
		{"menor", tokenFacts{IL: bajo}, cliente, false},
		{"AppContainer", tokenFacts{IL: medio, AppContainer: true}, cliente, false},
		{"restringido", tokenFacts{IL: medio, Restricted: true}, cliente, false},
		{"error leyendo el servidor", tokenFacts{IL: alto, Err: errors.New("acceso denegado")}, cliente, false},
		{"error leyendo el cliente", tokenFacts{IL: alto}, tokenFacts{Err: errors.New("x")}, false},
		{"integridad 0 del servidor", tokenFacts{}, cliente, false},
	} {
		if err := serverTrusted(c.server, c.client); (err == nil) != c.ok {
			t.Errorf("%s: serverTrusted = %v, quería ok=%v", c.name, err, c.ok)
		}
	}
}

func TestMensajePipeIntegridad(t *testing.T) {
	for _, loc := range []string{"es", "en"} {
		if m := i18n.Msg(loc, "ipc.err.pipe_low_integrity", i18n.A("name", "x")); m == "" || strings.HasPrefix(m, "ipc.err") {
			t.Errorf("%s: sin texto (%q)", loc, m)
		}
	}
}
