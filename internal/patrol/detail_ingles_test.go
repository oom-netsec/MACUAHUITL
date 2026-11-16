package patrol

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// El manifest va en el idioma canónico (inglés): el Detail de un equipo que sale de un error i18n se guarda en inglés,
// y el error sigue disponible para darlo en el idioma del cliente.
func TestManifestDetailEnIngles(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	perr := i18n.New("patrol.dev.partial", i18n.A("cut", 1, "reconnects", 1, "first", "show memory summary"))
	res := DeviceResult{State: "partial", Detail: perr.Error(), DetailErr: perr, CutCommands: []string{"show memory summary"}, Reconnects: 1}
	m, err := Finish(context.Background(), e.d, w, e.spec, 1, []DeviceResult{res})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(w.dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got Manifest
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := "1 command cut and 1 reconnect; first: show memory summary"
	if got.Devices[0].Detail != want {
		t.Errorf("Detail en el manifest = %q, quería %q", got.Devices[0].Detail, want)
	}
	if strings.Contains(string(b), "cortado") {
		t.Errorf("texto en español en el manifest: %s", b)
	}
	if m.Devices[0].DetailErr == nil {
		t.Error("el resultado devuelto perdió DetailErr (el cliente lo necesita en su idioma)")
	}
}
