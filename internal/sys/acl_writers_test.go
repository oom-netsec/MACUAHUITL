package sys

import (
	"slices"
	"strings"
	"testing"
)

// Escritura de otros en una carpeta de transferencia: cuentan las ACE de escritura de un SID ajeno (también solo-herencia), no las de
// lectura ni las del usuario, SYSTEM, Administradores, CREATOR OWNER y TrustedInstaller.
func TestForeignWriters(t *testing.T) {
	const user, every, users = "S-1-5-21-1-2-3-1001", "S-1-1-0", "S-1-5-32-545"
	for nombre, c := range map[string]struct {
		aces []ace
		want []string
	}{
		"solo propios":                   {[]ace{{sid: user, mask: fileAllAccess}, {sid: sidSystem, mask: fileAllAccess}, {sid: sidAdmins, mask: fileAllAccess}}, nil},
		"Everyone solo lee":              {[]ace{{sid: user, mask: fileAllAccess}, {sid: every, mask: 0x1200A9}}, nil},
		"Everyone escribe":               {[]ace{{sid: every, mask: 0x1301BF}}, []string{every}},
		"Users agrega archivos":          {[]ace{{sid: users, mask: fileAddFile}}, []string{users}},
		"solo-herencia cuenta":           {[]ace{{sid: users, mask: fileAllAccess, inheritOnly: true}}, []string{users}},
		"creator owner y TI":             {[]ace{{sid: sidCreatorOwner, mask: fileAllAccess}, {sid: sidTrustedInstaller, mask: fileAllAccess}}, nil},
		"tipo desconocido falla cerrado": {[]ace{{sid: "tipo-ace-5", mask: anyAccess}}, []string{"tipo-ace-5"}},
		"sin repetir":                    {[]ace{{sid: every, mask: genericAll}, {sid: every, mask: writeDAC}}, []string{every}},
	} {
		if got := foreignWriters(c.aces, user); !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, quería %v", nombre, got, c.want)
		}
	}
}

// Las órdenes copiables de arreglo: ninguna con ruta o SID hostil (cmd y shell), y las buenas llevan la ruta entre comillas (cmd).
func TestOrdenesDeArreglo(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	if got := IcaclsFix(`C:\Users\Ana María\recibido (1)`, user, []string{"S-1-1-0", "S-1-5-32-545"}); got != `icacls "C:\Users\Ana María\recibido (1)" /inheritance:r /remove "*S-1-1-0" /remove "*S-1-5-32-545" /grant:r "*`+user+`:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F"` {
		t.Errorf("icacls: %q", got)
	}
	for _, p := range []string{`C:\a"b`, `C:\a%TEMP%`, `C:\a^b`, `C:\a!b`, `C:\a$b`, "C:\\a`b", "C:\\a\nb", "C:\\a\r\nb", "C:\\a\u202eb", "C:\\a\u2066b", `C:\a&b`, `C:\a|b`, "C:\\a\x00b"} {
		if got := IcaclsFix(p, user, []string{"S-1-1-0"}); got != "" {
			t.Errorf("icacls(%q) = %q", p, got)
		}
		if got := ChmodFix("/"+strings.TrimPrefix(p, `C:\`), []string{"g+w"}); got != "" && !strings.Contains(p, "%") { // % es inofensivo en sh
			t.Errorf("chmod(%q) = %q", p, got)
		}
	}
	for _, sid := range []string{`S-1-1-0" & calc & "`, "S-1-5-18\n", "S-1-", "S-1-5-x", "", "S-1-5-1\u202e0"} {
		if got := IcaclsFix(`C:\x`, user, []string{sid}); got != "" {
			t.Errorf("sid %q: %q", sid, got)
		}
		if got := IcaclsFix(`C:\x`, sid, []string{"S-1-1-0"}); got != "" {
			t.Errorf("user %q: %q", sid, got)
		}
	}
	if IcaclsFix(`C:\x`, user, nil) != "" || ChmodFix("/x", nil) != "" || ChmodFix("/x", []string{"zz"}) != "" {
		t.Error("sin nada que quitar no hay orden")
	}
	for who, want := range map[string]string{"g+w": "chmod g-w /srv/in", "o+w": "chmod o-w /srv/in"} {
		if got := ChmodFix("/srv/in", []string{who}); got != want {
			t.Errorf("%s: %q", who, got)
		}
	}
	if got := ChmodFix("/srv/in", []string{"g+w", "o+w"}); got != "chmod g-w,o-w /srv/in" {
		t.Errorf("%q", got)
	}
}

func TestForeignOwnerPuro(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	for owner, want := range map[string]bool{user: false, sidSystem: false, sidAdmins: false, "S-1-5-21-1-2-3-1002": true, "S-1-1-0": true} {
		if foreignOwner(owner, user) != want {
			t.Errorf("%s: quería %v", owner, want)
		}
	}
}
