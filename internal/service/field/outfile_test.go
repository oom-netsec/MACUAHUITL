package field

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/service/servicetest"
)

// outFile nunca sigue un enlace ni reabre un archivo ajeno: si el nombre ya existe (archivo, enlace plantado),
// crea otro con sufijo.
func TestOutFileNoSigueEnlacesNiReusaNombres(t *testing.T) {
	d := servicetest.New(t)
	s := &fieldSvc{d: d}
	dir := filepath.Join(d.Outputs(), "console")
	os.MkdirAll(dir, 0o700)
	victima := filepath.Join(t.TempDir(), "victima")
	os.WriteFile(victima, []byte("intacta"), 0o600)
	now := time.Now()
	for i := 0; i < 4; i++ { // el nombre lleva la hora al segundo: se plantan los de los próximos segundos
		os.Symlink(victima, filepath.Join(dir, "console_ttyUSB0_"+now.Add(time.Duration(i)*time.Second).Format("20060102-150405")+".log"))
	}
	f, err := s.outFile("console", "console_ttyUSB0")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := os.Lstat(f.Name())
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("el archivo de salida debía ser nuevo y regular, no el enlace: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(victima); string(b) != "intacta" {
		t.Fatalf("se escribió en el destino del enlace: %q", b)
	}
	// y dos aperturas seguidas no comparten archivo
	g, err := s.outFile("console", "console_ttyUSB0")
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if g.Name() == f.Name() {
		t.Fatalf("dos aperturas dieron el mismo archivo: %s", g.Name())
	}
	if fi, _ := g.Stat(); fi.Mode().Perm() != 0o600 {
		t.Errorf("permisos %v", fi.Mode().Perm())
	}
}
