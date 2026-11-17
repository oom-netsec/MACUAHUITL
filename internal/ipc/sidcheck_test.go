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
	const bajo, medio, alto, sistema = 0x1000, 0x2000, 0x3000, 0x4000
	ok := tokenFacts{IL: medio}
	for _, c := range []struct {
		name   string
		label  uint32 // 0 = el pipe no tiene etiqueta (se rechaza)
		server tokenFacts
		client tokenFacts
		want   bool
	}{
		{"etiqueta igual", medio, ok, tokenFacts{IL: medio}, true},
		{"etiqueta mayor", alto, ok, tokenFacts{IL: medio}, true},
		{"etiqueta menor", bajo, ok, tokenFacts{IL: medio}, false},
		{"sin etiqueta, cliente medio", 0, ok, tokenFacts{IL: medio}, false},
		{"sin etiqueta, cliente bajo", 0, ok, tokenFacts{IL: bajo}, false},
		{"sin etiqueta, cliente alto", 0, ok, tokenFacts{IL: alto}, false},
		{"cliente alto, etiqueta media (tope medio)", medio, ok, tokenFacts{IL: alto}, true},
		{"cliente alto, etiqueta baja", bajo, ok, tokenFacts{IL: alto}, false},
		{"cliente alto, etiqueta media", medio, ok, tokenFacts{IL: alto}, true},
		{"cliente sistema, etiqueta media", medio, ok, tokenFacts{IL: sistema}, true},
		{"cliente bajo, etiqueta baja", bajo, ok, tokenFacts{IL: bajo}, true},
		{"cliente bajo, etiqueta media", medio, ok, tokenFacts{IL: bajo}, true},
		{"cliente con integridad 0", alto, ok, tokenFacts{}, false},
		{"error leyendo el cliente", alto, ok, tokenFacts{IL: medio, Err: errors.New("x")}, false},
		{"AppContainer", alto, tokenFacts{IL: medio, AppContainer: true}, ok, false},
		{"restringido", alto, tokenFacts{IL: medio, Restricted: true}, ok, false},
		{"error leyendo el servidor", alto, tokenFacts{Err: errors.New("acceso denegado")}, ok, false},
	} {
		if err := serverTrusted(c.label, c.server, c.client); (err == nil) != c.want {
			t.Errorf("%s: serverTrusted = %v, quería ok=%v", c.name, err, c.want)
		}
	}
}

func TestMensajePipeIntegridad(t *testing.T) {
	for _, loc := range []string{"es", "en"} {
		for _, code := range []string{"ipc.err.pipe_low_integrity", "ipc.err.server_low_integrity"} {
			if m := i18n.Msg(loc, code, i18n.A("name", "x")); m == "" || strings.HasPrefix(m, "ipc.err") {
				t.Errorf("%s %s: sin texto (%q)", loc, code, m)
			}
		}
	}
}
