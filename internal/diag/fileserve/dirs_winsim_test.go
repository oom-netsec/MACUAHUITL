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
	} {
		if got := sinLetraDeUnidad(p); got != want {
			t.Errorf("sinLetraDeUnidad(%q)=%v, quería %v", p, got, want)
		}
	}
}
