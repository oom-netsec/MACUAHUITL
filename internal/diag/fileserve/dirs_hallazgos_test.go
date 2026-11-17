package fileserve

import (
	"os"
	"path/filepath"
	"testing"
)

// fijaFinalPath simula la ruta final del handle (en Windows la que resuelve GetFinalPathNameByHandle).
func fijaFinalPath(t *testing.T, f func(*os.File) (string, error)) {
	t.Helper()
	old := finalPath
	finalPath = f
	t.Cleanup(func() { finalPath = old })
}

// Una junction en un tramo intermedio no la resuelve EvalSymlinks: la ruta final del handle abierto es la que manda,
// tanto para la carpeta (OpenDir) como para el archivo publicado y el abierto con OpenFrom.
func TestRutaFinalDelHandleEntraEnLaListaNegada(t *testing.T) {
	base := realTemp(t)
	t.Setenv("HOME", realTemp(t))
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	dir, prohibida := filepath.Join(base, "ok"), filepath.Join(base, "prohibida")
	os.MkdirAll(dir, 0o700)
	os.MkdirAll(prohibida, 0o700)
	file := filepath.Join(dir, "a.bin")
	os.WriteFile(file, []byte("x"), 0o600)

	fijaFinalPath(t, func(*os.File) (string, error) { return filepath.Join(prohibida, "sub"), nil })
	if r, _, err := OpenDir(dir, prohibida); err == nil {
		r.Close()
		t.Error("OpenDir debió rechazar: el handle cae en la lista negada")
	}
	if _, _, err := publish([]string{file}, []string{prohibida}); err == nil {
		t.Error("publish debió rechazar: el handle cae en la lista negada")
	}
	if f, _, err := OpenFrom(dir, "a.bin", prohibida); err == nil {
		f.Close()
		t.Error("OpenFrom debió rechazar: el handle cae en la lista negada")
	}

	fijaFinalPath(t, func(f *os.File) (string, error) { return f.Name(), nil })
	if r, _, err := OpenDir(dir, prohibida); err != nil {
		t.Errorf("control: %v", err)
	} else {
		r.Close()
	}
	if _, _, err := publish([]string{file}, []string{prohibida}); err != nil {
		t.Errorf("control: %v", err)
	}
}

// Con HOME en otra carpeta (Git for Windows, Emacs) el perfil real de la cuenta sigue protegido.
func TestWindowsHomeFalsoNoAbreElPerfilReal(t *testing.T) {
	fijaGOOS(t, "windows")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", realTemp(t))
	perfil := realTemp(t)
	old := accountHome
	accountHome = func() string { return perfil }
	t.Cleanup(func() { accountHome = old })
	startup := filepath.Join(perfil, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
	os.MkdirAll(startup, 0o700)
	if _, err := ValidateDir(startup); err == nil {
		t.Error("Startup del perfil real debió rechazarse con HOME en otra carpeta")
	}
}

// APPDATA y LOCALAPPDATA entran en la lista aunque no cuelguen de HOME.
func TestWindowsAppDataDelEntornoEsSensible(t *testing.T) {
	fijaGOOS(t, "windows")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", realTemp(t))
	app := realTemp(t)
	t.Setenv("APPDATA", app)
	if _, err := ValidateDir(app); err == nil {
		t.Error("APPDATA debió rechazarse")
	}
}

// Una carpeta extra (DenyDirs) alcanzada por un enlace también se rechaza por su ruta real.
func TestDenyExtraSeResuelveAlEnlace(t *testing.T) {
	base := realTemp(t)
	t.Setenv("HOME", realTemp(t))
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	data := filepath.Join(base, "data")
	os.MkdirAll(data, 0o700)
	enlace := filepath.Join(base, "enlace")
	if err := os.Symlink(data, enlace); err != nil {
		t.Skip(err)
	}
	if _, err := ValidateDir(data, enlace); err == nil {
		t.Error("la ruta real de una carpeta extra debió rechazarse")
	}
}

// Una UNC no toca la red: se rechaza por la letra de unidad antes de resolver ni consultar nada.
func TestPublishUNCNoTocaLaRuta(t *testing.T) {
	old, oldEx, oldEv := goos, exigeUnidad, evalSymlinks
	exigeUnidad = true
	evalSymlinks = func(string) (string, error) { t.Error("evalSymlinks no debió llamarse"); return "", os.ErrNotExist }
	t.Cleanup(func() { goos, exigeUnidad, evalSymlinks = old, oldEx, oldEv })
	unc := string(filepath.Separator) + string(filepath.Separator) + "host" + string(filepath.Separator) + "share" + string(filepath.Separator) + "x"
	if !filepath.IsAbs(unc) { // en Linux «//host/share/x» es absoluta
		t.Skip()
	}
	if _, _, err := publish([]string{unc}, nil); err == nil {
		t.Error("debió rechazarse")
	}
}
