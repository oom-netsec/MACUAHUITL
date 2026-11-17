package systest

import (
	"os/exec"
	"testing"
)

// Junction crea link como junction hacia target (mklink /J); salta la prueba si no se puede.
func Junction(t testing.TB, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("mklink /J no disponible: %v %s", err, out)
	}
}
