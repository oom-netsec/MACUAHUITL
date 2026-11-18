package service

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

func simulaWindows(t *testing.T) {
	t.Helper()
	old := OutputsGOOS
	OutputsGOOS = "windows"
	t.Cleanup(func() { OutputsGOOS = old })
}

// 2.4 (POSIBLE BUG 3): en Windows la carpeta de salidas debe empezar con letra de unidad. Una UNC abriría SMB (sale de la red
// fuera de EgressGuard y filtra el hash NTLM) y escribiría ahí. El rechazo es ANTES de tocar la ruta; la misma función sirve a
// Ajustes, a JobSpec.output_dir y a diag OutputDir.
// Una relativa simple conserva su motivo «relativa» también en Windows, y tampoco toca la ruta.
func TestCheckOutputsWindowsRelativaConservaSuMotivo(t *testing.T) {
	simulaWindows(t)
	for _, dir := range []string{"x", "rel/x", "\u202e" + `C:\x`} {
		_, err := CheckOutputs(dir, NewCoreSettings("fabrica", t.TempDir()), true)
		var e *i18n.Error
		if !errors.As(err, &e) || e.Code != "prefs.outputs.relativa" {
			t.Errorf("%q: %v", dir, err)
		}
	}
}

func TestCheckOutputsWindowsSinLetraDeUnidadSeRechazaSinTocarLaRuta(t *testing.T) {
	simulaWindows(t)
	for _, dir := range []string{`\\10.0.0.9\x\out`, `\\srv\share`, `//10.0.0.9/x/out`, `\\?\C:\x`, `\\?\UNC\10.0.0.9\x`, `\\.\pipe\x`, `\\.\C:\x`,
		`\??\C:\x`, `\\?\Volume{12345678-1234-1234-1234-123456789abc}\x`, `\x`, `/x`} {
		dir := strings.ReplaceAll(dir, `\u202e`, "\u202e")
		_, err := CheckOutputs(dir, NewCoreSettings("fabrica", t.TempDir()), true)
		var e *i18n.Error
		if !errors.As(err, &e) || e.Code != "prefs.outputs.sin_unidad" {
			t.Errorf("%q: %v", dir, err)
			continue
		}
		if i18n.Reason(e.Code) != "prefs.outputs.sin_unidad" || !strings.Contains(e.Localize(i18n.En), "drive letter") || !strings.Contains(e.Localize(i18n.Es), "letra de unidad") {
			t.Errorf("%q: textos %q / %q", dir, e.Localize(i18n.En), e.Localize(i18n.Es))
		}
	}
}

// Con letra de unidad la regla no estorba: la ruta sigue su camino (aquí falla después, por no existir en el anfitrión).
func TestCheckOutputsWindowsConLetraDeUnidadSigueAdelante(t *testing.T) {
	simulaWindows(t)
	_, err := CheckOutputs(`C:\no-existe-43d\x`, NewCoreSettings("fabrica", t.TempDir()), false)
	var e *i18n.Error
	if !errors.As(err, &e) || e.Code == "prefs.outputs.sin_unidad" {
		t.Fatalf("%v", err)
	}
}

// 4.7: la orden icacls que se muestra para copiar. Nada que viene de la ruta o de un SID puede salir de las comillas ni
// expandirse en cmd (%, ^, !, $, comillas, acento grave, saltos, bidi): con una ruta así no se emite la orden.
func TestIcaclsNingunaOrdenConRutaOSIDHostil(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1001"
	hostiles := []string{`C:\a"b`, `C:\a%TEMP%`, `C:\a^b`, `C:\a!b`, `C:\a$b`, "C:\\a`b", "C:\\a\nb", "C:\\a\rb", "C:\\a\u2028b", "C:\\a\u0085b",
		"C:\\a\u202eb", "C:\\a\u2066b", "C:\\a\u200bb", "C:\\a\u00a0b", `C:\a&b`, `C:\a|b`, `C:\a;b`, `C:\a<b`, `C:\a>b`, "C:\\a\x00b", `C:\a'b`}
	for _, dir := range hostiles {
		err := windowsOutputsErr(dir, &sys.PrivateDirError{Reason: sys.PrivateDirACL, Path: dir, SID: "S-1-1-0", SIDs: []string{"S-1-1-0"}, User: user})
		var e *i18n.Error
		if !errors.As(err, &e) || e.Code != "prefs.outputs.permisos_win" {
			t.Errorf("%q: %v", dir, err)
			continue
		}
		for _, l := range []string{i18n.Es, i18n.En} {
			if strings.Contains(e.Localize(l), "icacls") {
				t.Errorf("%q (%s): emitió orden: %s", dir, l, e.Localize(l))
			}
		}
	}
	// SID falso: solo S-1-<números separados por guion>; lo demás (comillas, espacios, &) no es un SID y no se emite orden.
	falsos := []string{`S-1-1-0" & calc & "`, "S-1-5-18\n", `S-1-5-x`, `S-1-`, `S-1-5-32-544 /remove "*S-1-1-0`, `S-1-5-21-1"`, "S-1-5-1\u202e0", `S-2-5-18`, `S-1-5--1`, ``}
	for _, sid := range falsos {
		for _, caso := range []struct {
			nombre, usr string
			sids        []string
		}{{"SID de la ACL", user, []string{sid}}, {"SID del usuario", sid, []string{"S-1-1-0"}}} {
			err := windowsOutputsErr(`C:\Users\ana\salidas`, &sys.PrivateDirError{Reason: sys.PrivateDirACL, Path: `C:\Users\ana\salidas`, SID: "x", SIDs: caso.sids, User: caso.usr})
			var e *i18n.Error
			if !errors.As(err, &e) || e.Code != "prefs.outputs.permisos_win" {
				t.Errorf("%s %q: %v", caso.nombre, sid, err)
			}
		}
	}
}

// Ruta con espacios, acentos y paréntesis: la orden sale, con la ruta entre comillas dobles y nada fuera de ellas.
func TestIcaclsRutaConEspaciosVaEntreComillas(t *testing.T) {
	const dir = `C:\Users\Ana María\Mis salidas (1)`
	err := windowsOutputsErr(dir, &sys.PrivateDirError{Reason: sys.PrivateDirACL, Path: dir, SID: "S-1-1-0", SIDs: []string{"S-1-1-0"}, User: "S-1-5-21-1-2-3-1001"})
	var e *i18n.Error
	if !errors.As(err, &e) || e.Code != "prefs.outputs.permisos_orden_win" {
		t.Fatalf("%v", err)
	}
	for _, l := range []string{i18n.Es, i18n.En} {
		if !strings.Contains(e.Localize(l), `icacls "`+dir+`" /inheritance:r /remove "*S-1-1-0" /grant:r`) {
			t.Errorf("%s: %s", l, e.Localize(l))
		}
	}
}

// 4.9: la orden chmod solo con rutas seguras de pegar en una terminal.
func TestChmodSoloConRutaSeguraTabla(t *testing.T) {
	for p, want := range map[string]bool{"/home/a/salidas": true, "/home/a/Música": true, "/a b": false, "/a\nb": false, "/a\u202eb": false, "/a\u2028b": false,
		"/a~b": false, "/a\u00a0b": false, "/a$b": false, "/a`b": false, `/a"b`: false, "/a'b": false, "/a;b": false, "/a&b": false, "/a|b": false,
		"/a*b": false, "/a(b": false, "/a\\b": false, "/a\u200bb": false, "/a\x00b": false, "/a!b": false, "/a#b": false, "/a<b": false} {
		if got := safeShellPath.MatchString(p); got != want {
			t.Errorf("safeShellPath(%q) = %v", p, got)
		}
	}
	for p, want := range map[string]bool{`C:\a b\c`: true, `C:\a(1)`: true, `C:\a%b`: false, `C:\a^b`: false, `C:\a!b`: false, `C:\a$b`: false, "C:\\a`b": false,
		"C:\\a\nb": false, "C:\\a\u202eb": false, `C:\a"b`: false, `C:\a&b`: false, "C:\\a\u00a0b": false} {
		if got := safeCmdPath.MatchString(p); got != want {
			t.Errorf("safeCmdPath(%q) = %v", p, got)
		}
	}
}

// 43d-2 bajo 4: una unidad de red mapeada (DRIVE_REMOTE) se rechaza con el mismo código que una UNC, antes de tocar la ruta.
func TestCheckOutputsWindowsUnidadDeRedMapeadaSeRechaza(t *testing.T) {
	simulaWindows(t)
	old := RemoteDrive
	RemoteDrive = func(p string) bool { return strings.HasPrefix(p, "Z:") }
	t.Cleanup(func() { RemoteDrive = old })
	_, err := CheckOutputs(`Z:\salidas`, NewCoreSettings("fabrica", t.TempDir()), true)
	var e *i18n.Error
	if !errors.As(err, &e) || e.Code != "prefs.outputs.sin_unidad" {
		t.Fatalf("%v", err)
	}
	_, err = CheckOutputs(`C:\no-existe-43d`, NewCoreSettings("fabrica", t.TempDir()), false)
	if !errors.As(err, &e) || e.Code == "prefs.outputs.sin_unidad" {
		t.Fatalf("una unidad local sigue su camino: %v", err)
	}
}

// En Windows ningún mensaje de la carpeta de salidas habla de permisos 0700 (no existen: son ACL).
func TestOutputsWindowsSinCeroSieteCeroCero(t *testing.T) {
	simulaWindows(t)
	err := noExisteErr(`C:\salidas`)
	var e *i18n.Error
	if !errors.As(err, &e) || e.Reason() != "prefs.outputs.no_existe" {
		t.Fatalf("el reason no cambia: %v", err)
	}
	for _, l := range []string{i18n.Es, i18n.En} {
		if s := i18n.In(l, err); strings.Contains(s, "0700") || !strings.Contains(s, `C:\salidas`) {
			t.Errorf("%v: %q", l, s)
		}
	}
	OutputsGOOS = "linux"
	if !strings.Contains(i18n.In(i18n.En, noExisteErr("/x")), "0700") {
		t.Error("en Linux sigue indicando 0700")
	}
}

// El texto de «no se pudo leer» lleva solo la causa del sistema: ni la llamada (GetFileAttributesEx, lstat) ni la ruta repetida.
func TestOutputsIlegibleSinApiCruda(t *testing.T) {
	err := causaSistema(&fs.PathError{Op: "GetFileAttributesEx", Path: `C:\x`, Err: errors.New("Access is denied.")})
	if err.Error() != "Access is denied." {
		t.Fatalf("got %q", err)
	}
	if causaSistema(errors.New("otro")).Error() != "otro" {
		t.Fatal("un error que no es PathError pasa igual")
	}
}
