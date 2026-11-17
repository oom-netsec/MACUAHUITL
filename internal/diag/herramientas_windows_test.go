package diag

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// 43d-3 (5.4, 5.5) [W]: la herramienta se resuelve por ruta absoluta del sistema, nunca por cwd ni PATH, y un
// SystemRoot falso del entorno no cambia la ruta.
func TestHerramientasWindowsNoSeResuelvenPorCwdNiPath(t *testing.T) {
	sys, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		t.Fatal(err)
	}
	want := sys + `\System32\PING.EXE`
	evil := t.TempDir()
	for _, n := range []string{"ping.exe", "tracert.exe", "nmap.exe", "dumpcap.exe"} {
		if err := os.WriteFile(filepath.Join(evil, n), []byte("MZ"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(evil)
	t.Setenv("PATH", evil+";.")
	t.Setenv("SystemRoot", evil)
	t.Setenv("windir", evil)
	t.Setenv("ProgramFiles", evil)
	t.Setenv("ProgramFiles(x86)", evil)
	for bin, tail := range map[string]string{"ping": `\System32\PING.EXE`, "tracert": `\System32\TRACERT.EXE`} {
		got, err := lookPath(bin)
		if err != nil || !strings.EqualFold(got, sys+tail) {
			t.Errorf("%s = %q, %v; quiero %q", bin, got, err, sys+tail)
		}
	}
	if got, _ := lookPath("ping"); !strings.EqualFold(got, want) {
		t.Errorf("ping = %q", got)
	}
	for _, bin := range []string{"nmap", "dumpcap"} {
		if got, err := lookPath(bin); err == nil && strings.HasPrefix(strings.ToLower(got), strings.ToLower(evil)) {
			t.Errorf("%s salió de la carpeta falsa: %q", bin, got)
		}
	}
	if env := strings.Join(childEnv(want), "|"); strings.Contains(strings.ToLower(env), strings.ToLower(evil)) {
		t.Errorf("el entorno del hijo lleva la carpeta falsa: %s", env)
	}
	// Y el comando del hijo corre desde la carpeta de la herramienta, no desde el cwd heredado.
	cmd := exec.Command(want)
	if _, _, err := confine(cmd); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(cmd.Dir, sys+`\System32`) {
		t.Errorf("cmd.Dir = %q", cmd.Dir)
	}
}
