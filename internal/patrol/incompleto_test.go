package patrol

import (
	"context"
	"errors"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
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

func TestSplitDeviceDir(t *testing.T) {
	for in, want := range map[string][2]string{
		"SW1_192.0.2.1":      {"SW1", "192.0.2.1"},
		"SW1_192.0.2.1_2222": {"SW1", "192.0.2.1"},
		"SW_A_192.0.2.1_22":  {"SW_A", "192.0.2.1"},
		"SW1_2001_db8__1":    {"SW1_2001_db8_", "1"}, // IPv6: el nombre no es reversible, se corta en el último «_» como siempre
		"solo":               {"solo", ""},
	} {
		if h, ip := SplitDeviceDir(in); h != want[0] || ip != want[1] {
			t.Errorf("SplitDeviceDir(%q) = %q, %q; quería %q", in, h, ip, want)
		}
	}
	if got := DeviceDirOf("SW1", Target{Address: "192.0.2.1", Port: 2222}); got != "SW1_192.0.2.1_2222" {
		t.Errorf("DeviceDirOf = %q", got)
	}
}

// Dos trabajos con el mismo nombre y el mismo segundo no comparten carpeta.
func TestNewWriterNoComparteCarpeta(t *testing.T) {
	root, now := t.TempDir(), time.Now()
	a, err := NewWriter(root, Spec{Name: "j"}, now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewWriter(root, Spec{Name: "j"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Dir() == b.Dir() {
		t.Fatalf("misma carpeta: %s", a.Dir())
	}
}

// incompletoDrv es el driver real con Run marcando Incomplete sin error (FTD que aceptó un solo prompt).
type incompletoDrv struct{ platform.Driver }

func (p *incompletoDrv) Run(ctx context.Context, cmd string, timeout time.Duration) (platform.Output, error) {
	out, err := p.Driver.Run(ctx, cmd, timeout)
	out.Incomplete = cmd != "show version" && err == nil
	return out, err
}

// Un Incomplete que el driver marca sin error llega a la evidencia con « · incompleto»; el equipo no falla.
func TestRunDeviceConservaIncompleteDelDriver(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	drv := &incompletoDrv{e.d.driver()}
	e.d.NewDriver = func() platform.Driver { return drv }
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if res.State != "completed" {
		t.Fatalf("res = %s %q", res.State, res.Detail)
	}
	var all string
	for _, f := range w.Files() {
		b, _ := os.ReadFile(filepath.Join(w.Dir(), f))
		all += string(b)
	}
	if !strings.Contains(all, " · incompleto =====") {
		t.Fatalf("la evidencia no marca incompleto:\n%s", all[:min(len(all), 600)])
	}
}

// desyncDrv devuelve la salida parcial de un comando con la sesión desincronizada.
type desyncDrv struct{ platform.Driver }

func (p *desyncDrv) Run(ctx context.Context, cmd string, timeout time.Duration) (platform.Output, error) {
	out, err := p.Driver.Run(ctx, cmd, timeout)
	if cmd != "show version" && err == nil {
		out.Incomplete = true
		return out, platform.ErrDesync
	}
	return out, err
}

// Patrol no reconecta dentro de un equipo: una sesión desincronizada (ErrDesync, detectada por la falta de eco del
// comando siguiente) falla el equipo con ese error, deja la salida parcial marcada como incompleta y la ronda
// siguiente abre una sesión nueva. Un cierre por calma, en cambio, no falla: solo marca la salida incompleta.
func TestRunDeviceFallaConSesionDesincronizada(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	drv := &desyncDrv{e.d.driver()}
	e.d.NewDriver = func() platform.Driver { return drv }
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if res.State != "failed" || !errors.Is(res.DetailErr, platform.ErrDesync) {
		t.Fatalf("res = %s %q %v", res.State, res.Detail, res.DetailErr)
	}
	var all string
	for _, f := range w.Files() {
		b, _ := os.ReadFile(filepath.Join(w.Dir(), f))
		all += string(b)
	}
	if !strings.Contains(all, " · incompleto =====") {
		t.Fatalf("sin marca de incompleto:\n%s", all[:min(len(all), 400)])
	}
}
