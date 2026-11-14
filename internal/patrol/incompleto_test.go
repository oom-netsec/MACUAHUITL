package patrol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
)

// La salida parcial de un comando fallido lleva la marca « · incompleto» en su cabecera.
func TestWriteMarcaLaSalidaIncompleta(t *testing.T) {
	w, err := NewWriter(t.TempDir(), Spec{Name: "j"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC)
	dev := Device{Host: "SW1", IP: "192.0.2.1"}
	for i, inc := range []bool{false, true} {
		out := platform.Output{Command: "show run", Text: "hostname SW1\n", Started: at, Incomplete: inc}
		if err := w.Write(dev, 1, at, out, false); err != nil {
			t.Fatal(i, err)
		}
	}
	b, _ := os.ReadFile(filepath.Join(w.Dir(), w.Files()[0]))
	hs := strings.Split(strings.TrimSpace(string(b)), "\n")
	if hs[0] != "===== 2026-11-06T10:00:00Z · show run =====" || hs[2] != "===== 2026-11-06T10:00:00Z · show run · incompleto =====" {
		t.Fatalf("cabeceras: %q", hs)
	}
}
