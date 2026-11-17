//go:build windows

package field

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// 2.1 en Windows: la subcarpeta de salidas es una junction hacia fuera de las salidas; no se escribe afuera.
func TestOutFileJunctionHaciaFueraNoEscribeAfuera(t *testing.T) {
	d := servicetest.New(t)
	s := &fieldSvc{d: d}
	fuera := t.TempDir()
	os.MkdirAll(d.Outputs(), 0o700)
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(d.Outputs(), "console"), fuera).CombinedOutput(); err != nil {
		t.Skipf("mklink /J no disponible: %v %s", err, out)
	}
	f, err := s.outFile("console", "console_COM3")
	if err == nil {
		f.Close()
		t.Fatalf("debía rechazar la junction, creó %s", f.Name())
	}
	if es, _ := os.ReadDir(fuera); len(es) != 0 {
		t.Fatalf("escribió fuera: %v", es)
	}
}
