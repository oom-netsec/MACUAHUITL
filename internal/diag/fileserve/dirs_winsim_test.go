package fileserve

import (
	"os"
	"path/filepath"
	"testing"
)

// fijaGOOS simula la rama de Windows de dirs.go en cualquier sistema (con rutas del sistema anfitrión).
func fijaGOOS(t *testing.T, so string) {
	t.Helper()
	old := goos
	goos = so
	t.Cleanup(func() { goos = old })
}

// TMP/TEMP en AppData, AppData\Local o AppData\Roaming no abre Startup, Roaming ni lo demás de AppData: solo
// <home>\AppData\Local\Temp es la carpeta temporal permitida.
func TestWindowsTempNoDependeDeTMP(t *testing.T) {
	fijaGOOS(t, "windows")
	home := realTemp(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	app := filepath.Join(home, "AppData")
	startup := filepath.Join(app, "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	otra := filepath.Join(app, "Local", "Otra")
	datos := filepath.Join(app, "Local", "MACUAHUITL", "data")
	tmpOK := filepath.Join(app, "Local", "Temp", "x")
	for _, d := range []string{startup, otra, datos, tmpOK} {
		os.MkdirAll(d, 0o700)
	}
	for _, tmp := range []string{app, filepath.Join(app, "Local"), filepath.Join(app, "Roaming")} {
		for _, v := range []string{"TMP", "TEMP", "TMPDIR"} {
			t.Setenv(v, tmp)
		}
		for _, bad := range []string{startup, filepath.Join(app, "Roaming"), otra, datos} {
			if _, err := ValidateDir(bad); err == nil {
				t.Errorf("TMP=%s: %s debió rechazarse", tmp, bad)
			}
		}
		if _, err := ValidateDir(tmpOK); err != nil {
			t.Errorf("TMP=%s: Temp\\x debe permitirse: %v", tmp, err)
		}
	}
}

// Las variables de Windows y la comparación no distinguen mayúsculas: SystemRoot=C:\WINDOWS bloquea C:\Windows\System32.
func TestWindowsListaSinDistinguirMayusculas(t *testing.T) {
	fijaGOOS(t, "windows")
	home := realTemp(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	sys := filepath.Join(realTemp(t), "windows", "System32")
	os.MkdirAll(sys, 0o700)
	t.Setenv("SystemRoot", filepath.Join(filepath.Dir(filepath.Dir(sys)), "WINDOWS"))
	if _, err := ValidateDir(sys); err == nil {
		t.Errorf("%s debió rechazarse con SystemRoot en otras mayúsculas", sys)
	}
	if !inside(filepath.Join(home, "appdata", "x"), filepath.Join(home, "AppData")) {
		t.Error("inside debe ignorar mayúsculas en Windows")
	}
	if inside(filepath.Join(home, "AppDataX"), filepath.Join(home, "AppData")) {
		t.Error("inside debe respetar el separador")
	}
}

// Predicado puro: solo una ruta que empieza con letra de unidad es válida en Windows (no \\?\, \\.\, \??\ ni UNC).
func TestSinLetraDeUnidad(t *testing.T) {
	for p, want := range map[string]bool{
		`C:\x`: false, `d:\x\y`: false, `C:`: false,
		`\\?\C:\x`: true, `\\.\C:\x`: true, `\??\C:\x`: true, `\\srv\share\x`: true, `\\?\UNC\srv\share`: true, `/etc`: true, ``: true, `1:\x`: true,
		// 2.7: volumen por GUID y variantes de dispositivo
		`\\?\Volume{12345678-1234-1234-1234-123456789abc}\x`: true, `\\?\GLOBALROOT\Device\x`: true, `\Device\HarddiskVolume1\x`: true, "\u202eC:\\x": true, "C\u200b:\\x": true,
	} {
		if got := sinLetraDeUnidad(p); got != want {
			t.Errorf("sinLetraDeUnidad(%q)=%v, quería %v", p, got, want)
		}
	}
}

// El perfil real de la cuenta cuenta como HOME exacto y como base de la regla de ocultos, no solo para la lista
// negada: con HOME=D:\home (Git for Windows) C:\Users\yo no puede ser FromDir/RecvDir ni sus carpetas con punto.
func TestWindowsPerfilRealEsHomeExactoYOcultos(t *testing.T) {
	fijaGOOS(t, "windows")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", realTemp(t))
	perfil := realTemp(t)
	old := accountHome
	accountHome = func() string { return perfil }
	t.Cleanup(func() { accountHome = old })
	oculta := filepath.Join(perfil, ".oculta")
	pass := filepath.Join(perfil, ".password-store")
	os.MkdirAll(oculta, 0o700)
	os.MkdirAll(pass, 0o700)
	for _, d := range []string{perfil, oculta, pass} {
		if _, err := ValidateDir(d); err == nil {
			t.Errorf("%s debió rechazarse (perfil real con HOME en otra carpeta)", d)
		}
	}
}

// B3: los perfiles de PowerShell (Documents\WindowsPowerShell y Documents\PowerShell, también con Documents redirigida a OneDrive)
// los ejecuta Windows al abrir una consola: ni se publica ni se recibe ahí. Startup ya queda cubierto por AppData. Documents a secas no.
func TestWindowsPerfilesDePowerShellYStartupRechazados(t *testing.T) {
	fijaGOOS(t, "windows")
	home := realTemp(t)
	oneDrive := realTemp(t) // OneDrive fuera del perfil (cuentas con otra ubicación)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("OneDrive", oneDrive)
	t.Setenv("OneDriveConsumer", "")
	t.Setenv("OneDriveCommercial", "")
	var malas []string
	for _, base := range []string{filepath.Join(home, "Documents"), filepath.Join(home, "OneDrive", "Documents"), filepath.Join(oneDrive, "Documents")} {
		for _, ps := range []string{"WindowsPowerShell", "PowerShell"} {
			malas = append(malas, filepath.Join(base, ps), filepath.Join(base, ps, "Modules"), filepath.Join(base, ps, "Modules", "x"))
		}
	}
	malas = append(malas, filepath.Join(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"))
	buenas := []string{filepath.Join(home, "Documents", "firmware"), filepath.Join(home, "Documents", "PowerShellNotas"), filepath.Join(oneDrive, "Documents", "firmware")}
	for _, d := range append(append([]string{}, malas...), buenas...) {
		os.MkdirAll(d, 0o700)
	}
	for _, d := range malas {
		if _, err := ValidateDir(d); err == nil {
			t.Errorf("%s debió rechazarse", d)
		}
	}
	for _, d := range buenas {
		if _, err := ValidateDir(d); err != nil {
			t.Errorf("%s debe permitirse: %v", d, err)
		}
	}
}

// 43d-2 bajo 1: Documents localizada o movida (FOLDERID_Documents, en otra unidad) también guarda los perfiles de PowerShell.
func TestWindowsPerfilesDePowerShellEnDocumentosMovida(t *testing.T) {
	fijaGOOS(t, "windows")
	home, movida := realTemp(t), realTemp(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("OneDrive", "")
	old := documentsDir
	documentsDir = func() string { return movida }
	t.Cleanup(func() { documentsDir = old })
	mala := filepath.Join(movida, "WindowsPowerShell", "Modules")
	os.MkdirAll(mala, 0o700)
	if _, err := ValidateDir(mala); err == nil {
		t.Errorf("%s debió rechazarse", mala)
	}
}
