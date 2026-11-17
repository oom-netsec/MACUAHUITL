package field

import (
	"path/filepath"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/serialcon"
	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// 43d-1 (1.11): un puerto serie hostil no llega a outFile o, si llega, el registro cae dentro de outputs/console.
func TestPuertoSerieHostilNoSacaElRegistroDeLaCarpeta(t *testing.T) {
	d := servicetest.New(t)
	s := &fieldSvc{d: d}
	salidas := filepath.Join(d.Outputs(), "console")
	for _, p := range []string{
		"../x", `..\x`, "x", "COM1:x", `C:\x`, `C:x`, `\\?\C:\x`, `\\.\pipe\x`, `\\host\share\x`, "/etc/passwd", "/dev/../etc/passwd",
		"/dev/../../x", "/dev/ttyUSB0/../../x", "/devx/ttyUSB0", "COM1 ", "COM1.", "COM01", "CON", "NUL", "",
	} {
		cfg, err := serialcon.Config{Path: p, Baud: 9600}.Normalize()
		if err != nil {
			continue // rechazado antes de abrir nada
		}
		if filepath.Base(cfg.Path) != filepath.Base(filepath.Clean(cfg.Path)) {
			t.Errorf("%q: Base inestable", p)
		}
		f, err := s.outFile("console", "console_"+filepath.Base(cfg.Path))
		if err != nil {
			continue
		}
		if filepath.Dir(f.Name()) != salidas {
			t.Errorf("%q: el registro cayó en %s", p, f.Name())
		}
		f.Close()
	}
}
