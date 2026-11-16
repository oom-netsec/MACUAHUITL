package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// windowsOutputsErr arma el error de la variante de Windows a partir del rechazo de sys.PrivateDir (ADR 0012, c).
func TestWindowsOutputsErr(t *testing.T) {
	const dir = `C:\Users\ana\salidas`
	casos := []struct {
		nombre string
		in     *sys.PrivateDirError
		code   string
		reason string // lo que el front ve en metadata.code
		es, en []string
	}{
		{"otro dueño", &sys.PrivateDirError{Reason: sys.PrivateDirOwner, Path: dir, SID: "S-1-5-18"}, "prefs.outputs.otro_dueno", "otro_dueno", nil, nil},
		{"ACL con orden", &sys.PrivateDirError{Reason: sys.PrivateDirACL, Path: dir, SID: "S-1-5-32-545, S-1-1-0", SIDs: []string{"S-1-5-32-545", "S-1-1-0"}, User: "S-1-5-21-1-2-3-1001"}, "prefs.outputs.permisos_orden.windows", "permisos",
			[]string{"prefs.outputs.permisos:", `icacls "C:\Users\ana\salidas" /inheritance:r`, `/remove "*S-1-5-32-545" /remove "*S-1-1-0"`, `"*S-1-5-21-1-2-3-1001:(OI)(CI)F"`, `"*S-1-5-18:(OI)(CI)F"`, `"*S-1-5-32-544:(OI)(CI)F"`},
			[]string{"prefs.outputs.permisos:", "icacls ", `/remove "*S-1-5-32-545" /remove "*S-1-1-0"`, `"*S-1-5-18:(OI)(CI)F"`}},
		{"ancestro", &sys.PrivateDirError{Reason: sys.PrivateDirAncestor, Path: `C:\Compartida`, SID: "S-1-1-0"}, "prefs.outputs.ancestro_inseguro.windows", "ancestro_inseguro",
			[]string{"prefs.outputs.ancestro_inseguro:", "S-1-1-0", `C:\Compartida`}, []string{"prefs.outputs.ancestro_inseguro:", "S-1-1-0", `C:\Compartida`}},
		{"ilegible", &sys.PrivateDirError{Reason: sys.PrivateDirRead, Path: `C:\Users`, Err: errors.New("boom")}, "prefs.outputs.ilegible_ruta", "ilegible", nil, nil},
	}
	for _, c := range casos {
		err := windowsOutputsErr(dir, c.in)
		var e *i18n.Error
		if !errors.As(err, &e) || e.Code != c.code {
			t.Errorf("%s: %v", c.nombre, err)
			continue
		}
		if got := i18n.Reason(e.Code); got != "prefs.outputs."+c.reason {
			t.Errorf("%s: reason %q", c.nombre, got)
		}
		for _, want := range c.es {
			if !strings.Contains(e.Localize(i18n.Es), want) {
				t.Errorf("%s (es): falta %q en %q", c.nombre, want, e.Localize(i18n.Es))
			}
		}
		for _, want := range c.en {
			if !strings.Contains(e.Localize(i18n.En), want) {
				t.Errorf("%s (en): falta %q en %q", c.nombre, want, e.Localize(i18n.En))
			}
		}
	}
}

// Una ruta con %, $ o comillas no se pega en cmd tal cual: sin orden, solo el motivo.
func TestWindowsOutputsErrSinOrdenSiLaRutaNoEsSegura(t *testing.T) {
	for _, dir := range []string{`C:\a%TEMP%`, `C:\a$x`, "C:\\a`b"} {
		err := windowsOutputsErr(dir, &sys.PrivateDirError{Reason: sys.PrivateDirACL, Path: dir, SID: "S-1-5-32-545"})
		var e *i18n.Error
		if !errors.As(err, &e) || e.Code != "prefs.outputs.permisos.windows" {
			t.Errorf("%q: %v", dir, err)
		}
	}
}

// La orden da el control al SID del usuario, nunca a %USERNAME%: en un dominio, una cuenta local con el mismo nombre
// recibiría el acceso. Sin el SID del usuario no hay orden.
func TestWindowsOutputsErrOrdenConSIDDelUsuario(t *testing.T) {
	const dir = `C:\Users\ana\salidas`
	pe := &sys.PrivateDirError{Reason: sys.PrivateDirACL, Path: dir, SID: "S-1-1-0", SIDs: []string{"S-1-1-0"}}
	var e *i18n.Error
	if err := windowsOutputsErr(dir, pe); !errors.As(err, &e) || e.Code != "prefs.outputs.permisos.windows" {
		t.Fatalf("sin SID del usuario debe salir sin orden: %v", err)
	}
	pe.User = "S-1-5-21-1-2-3-1001"
	err := windowsOutputsErr(dir, pe)
	if !errors.As(err, &e) || e.Code != "prefs.outputs.permisos_orden.windows" {
		t.Fatalf("con SID: %v", err)
	}
	for _, l := range []string{i18n.Es, i18n.En} {
		if m := e.Localize(l); strings.Contains(m, "USERNAME") || !strings.Contains(m, `"*S-1-5-21-1-2-3-1001:(OI)(CI)F"`) {
			t.Errorf("%s: %s", l, m)
		}
	}
}
