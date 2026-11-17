//go:build windows

package fileserve

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Los prefijos de dispositivo y las UNC no pasan por la lista de carpetas sensibles: se rechazan.
func TestWindowsRechazaPrefijosDeDispositivo(t *testing.T) {
	d := realTemp(t)
	for _, p := range []string{`\\?\` + d, `\\.\` + d, `\??\` + d} {
		if _, err := ValidateDir(p); err == nil {
			t.Errorf("%s debió rechazarse", p)
		}
	}
}

// Una junction en un tramo intermedio hacia una carpeta negada no se salta la lista: EvalSymlinks no la resuelve, pero
// la ruta final del handle abierto sí cae en la negada. Vale para la carpeta (OpenDir) y para el archivo publicado.
func TestWindowsJunctionIntermediaHaciaCarpetaNegada(t *testing.T) {
	base := realTemp(t)
	prohibida := filepath.Join(base, "prohibida")
	if err := os.MkdirAll(filepath.Join(prohibida, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(prohibida, "sub", "a.bin")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	j := filepath.Join(base, "j")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", j, prohibida).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if r, _, err := OpenDir(filepath.Join(j, "sub"), prohibida); err == nil {
		r.Close()
		t.Error("OpenDir por la junction debió rechazarse")
	}
	if _, _, err := publish([]string{filepath.Join(j, "sub", "a.bin")}, []string{prohibida}); err == nil {
		t.Error("publish por la junction debió rechazarse")
	}
	if f, _, err := OpenFrom(filepath.Join(j, "sub"), "a.bin", prohibida); err == nil {
		f.Close()
		t.Error("OpenFrom por la junction debió rechazarse")
	}
}

// 2.6: la carpeta negada pedida por su nombre corto 8.3 (PROGRA~1) se rechaza igual: la ruta final del handle es la larga.
func TestWindowsNombreCortoDeCarpetaNegadaSeRechaza(t *testing.T) {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		t.Skip("sin ProgramFiles")
	}
	short := sys.ShortPath(pf)
	if short == "" {
		t.Skip("sin nombres cortos en este volumen")
	}
	if strings.EqualFold(short, pf) {
		t.Skip("ProgramFiles no tiene nombre corto distinto")
	}
	for _, p := range []string{short, filepath.Join(short, "Common Files")} {
		if r, _, err := OpenDir(p); err == nil {
			r.Close()
			t.Errorf("%s (8.3) debió rechazarse", p)
		}
	}
}

// 2.7: volumen por GUID (\\?\Volume{...}\) se rechaza antes de tocar la ruta.
func TestWindowsVolumenPorGUIDSeRechaza(t *testing.T) {
	for _, p := range []string{`\\?\Volume{12345678-1234-1234-1234-123456789abc}\x`, `\\?\GLOBALROOT\Device\HarddiskVolume1\x`, `\\.\PhysicalDrive0`} {
		if _, err := ValidateDir(p); err == nil {
			t.Errorf("%s debió rechazarse", p)
		}
	}
}
