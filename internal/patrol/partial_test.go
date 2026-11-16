package patrol

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"errors"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/platform/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// cutState es lo que comparten los drivers de una prueba: qué comandos se cortan (una vez cada uno), qué corrió y
// cuántas sesiones se abrieron y se cerraron.
type cutState struct {
	mu            sync.Mutex
	cut           map[string]error // comando -> error que devuelve la primera vez que corre
	ran           []string
	opened, close int
	failOpenFrom  int    // desde esta sesión (1 = la primera), Open falla
	onCut         func() // se llama al cortar un comando
}

type cutDrv struct {
	platform.Driver
	st *cutState
}

func newCut(t *testing.T, e *env, cut map[string]error) *cutState {
	t.Helper()
	st := &cutState{cut: cut}
	e.d.NewDriver = func() platform.Driver {
		st.mu.Lock()
		defer st.mu.Unlock()
		st.opened++
		return &cutDrv{Driver: iosxe.New(), st: st}
	}
	return st
}

func (p *cutDrv) Open(ctx context.Context, r io.Reader, w io.Writer, en *secret.Secret) error {
	p.st.mu.Lock()
	fail := p.st.failOpenFrom > 0 && p.st.opened >= p.st.failOpenFrom
	p.st.mu.Unlock()
	if fail {
		en.Destroy()
		return platform.ErrEnableFailed
	}
	return p.Driver.Open(ctx, r, w, en)
}

func (p *cutDrv) Close() {
	p.st.mu.Lock()
	p.st.close++
	p.st.mu.Unlock()
	p.Driver.Close()
}

func (p *cutDrv) Run(ctx context.Context, cmd string, timeout time.Duration) (platform.Output, error) {
	p.st.mu.Lock()
	p.st.ran = append(p.st.ran, cmd)
	err, cut := p.st.cut[cmd]
	delete(p.st.cut, cmd)
	hook := p.st.onCut
	p.st.mu.Unlock()
	if cut {
		if hook != nil {
			hook()
		}
		return platform.Output{Command: cmd, Text: "parcial\n", Started: time.Now()}, err
	}
	return p.Driver.Run(ctx, cmd, timeout)
}

func (s *cutState) count(cmd string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.ran {
		if c == cmd {
			n++
		}
	}
	return n
}

func runPartial(t *testing.T, e *env, ctx context.Context) (DeviceResult, *Writer) {
	t.Helper()
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	return RunDevice(ctx, e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {}), w
}

func evidence(w *Writer) string {
	var all string
	for _, f := range w.Files() {
		b, _ := os.ReadFile(filepath.Join(w.Dir(), f))
		all += string(b)
	}
	return all
}

func TestComandoCortadoDejaElEquipoParcial(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	var states []string
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(p Progress) { states = append(states, p.State) })
	if res.State != "partial" || res.Reconnects != 1 || !slices.Equal(res.CutCommands, []string{"show running-config"}) {
		t.Fatalf("res = %+v", res)
	}
	var c interface{ Reason() string }
	if !errors.As(res.DetailErr, &c) || c.Reason() != "patrol.dev.partial" || res.Detail != "1 comando cortado y 1 reconexión; el primero: show running-config" {
		t.Fatalf("detalle = %q %v", res.Detail, res.DetailErr)
	}
	if st.count("show running-config") != 1 || st.count("show ip interface brief") != 1 {
		t.Fatalf("corrida: %v", st.ran)
	}
	if st.opened != 2 || st.close != 2 {
		t.Fatalf("sesiones abiertas=%d cerradas=%d", st.opened, st.close)
	}
	if !strings.Contains(evidence(w), "show running-config · incomplete =====") {
		t.Fatal("el cortado no quedó marcado incompleto")
	}
	if n := slices.Index(states, "connecting"); n < 0 || slices.Index(states[n+1:], "connecting") < 0 {
		t.Fatalf("falta el connecting de la reconexión: %v", states)
	}
	var buf bytes.Buffer
	e.d.Audit.Export(context.Background(), &buf, time.Time{}, time.Now().Add(time.Hour))
	out := buf.String()
	if !strings.Contains(out, "device.reconnect") || !strings.Contains(out, `command=\"show running-config\"`) || !strings.Contains(out, "attempt=1") || !strings.Contains(out, "state=partial") {
		t.Fatalf("auditoría:\n%s", out)
	}
}

func TestTresCortesFallanElEquipo(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	newCut(t, e, map[string]error{"show version": platform.ErrPromptTimeout, "show running-config": platform.ErrClosed, "show ip interface brief": platform.ErrPromptTimeout})
	res, _ := runPartial(t, e, context.Background())
	if res.State != "failed" || res.Reconnects != maxReconnects || !errors.Is(res.DetailErr, platform.ErrPromptTimeout) {
		t.Fatalf("res = %+v", res)
	}
}

func TestFinDeVentanaNoReconecta(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": fmt.Errorf("%w: %w", platform.ErrPromptTimeout, context.Canceled)})
	ctx, cancel := context.WithCancelCause(context.Background())
	st.onCut = func() { cancel(ErrWindowEnded) }
	res, _ := runPartial(t, e, ctx)
	if res.State != "failed" || !errors.Is(res.DetailErr, ErrWindowEnded) || st.opened != 1 || res.Reconnects != 0 {
		t.Fatalf("res = %+v opened=%d", res, st.opened)
	}
}

func TestErrorDeEvidenciaNoReconecta(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	st.onCut = func() { // la evidencia ya no se puede escribir
		filepath.Walk(w.Dir(), func(p string, fi os.FileInfo, _ error) error {
			if fi != nil && !fi.IsDir() {
				os.Chmod(p, 0o400)
			}
			return nil
		})
	}
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if res.State != "failed" || st.opened != 1 || res.Reconnects != 0 {
		t.Fatalf("res = %+v opened=%d", res, st.opened)
	}
}

func TestReconexionFallidaFallaElEquipo(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	st.failOpenFrom = 2
	res, _ := runPartial(t, e, context.Background())
	if res.State != "failed" || !errors.Is(res.DetailErr, platform.ErrEnableFailed) {
		t.Fatalf("res = %+v", res)
	}
	if res.Reconnects != 1 || len(res.CutCommands) != 1 { // el manifest conserva el rastro aunque el equipo falle
		t.Fatalf("rastro: %+v", res)
	}
	if st.close != 2 {
		t.Fatalf("cerradas = %d", st.close)
	}
}

func TestPreVuelveACorrerEnLaSesionNueva(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.d.Playbooks = append(e.d.Playbooks, playbook.Playbook{ID: "ios-xe/pre-prueba", Platform: "ios-xe", Name: "pre", Pre: []string{"show clock"},
		Commands: []playbook.Command{{Text: "show version", Timeout: time.Minute}, {Text: "show running-config", Timeout: time.Minute}, {Text: "show ip interface brief", Timeout: time.Minute}}})
	e.spec.PlaybookIDs, e.spec.CustomCommands = []string{"ios-xe/pre-prueba"}, ""
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	res, w := runPartial(t, e, context.Background())
	if res.State != "partial" || st.count("show clock") != 2 {
		t.Fatalf("res = %+v ran=%v", res, st.ran)
	}
	if n := strings.Count(evidence(w), "show clock"); n != 1 {
		t.Fatalf("el Pre repetido no debe ir a la evidencia: %d", n)
	}
}

func TestCorteEnElUltimoComandoNoReconecta(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.spec.CustomCommands = "show version\nshow running-config"
	st := newCut(t, e, map[string]error{"show running-config": platform.ErrPromptTimeout})
	res, _ := runPartial(t, e, context.Background())
	if res.State != "partial" || res.Reconnects != 0 || st.opened != 1 || !slices.Equal(res.CutCommands, []string{"show running-config"}) {
		t.Fatalf("res = %+v opened=%d", res, st.opened)
	}
}

func TestPreCortadoNoSeRepite(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.d.Playbooks = append(e.d.Playbooks, playbook.Playbook{ID: "ios-xe/pre-prueba", Platform: "ios-xe", Name: "pre", Pre: []string{"show clock"},
		Commands: []playbook.Command{{Text: "show version", Timeout: time.Minute}, {Text: "show running-config", Timeout: time.Minute}}})
	e.spec.PlaybookIDs, e.spec.CustomCommands = []string{"ios-xe/pre-prueba"}, ""
	st := newCut(t, e, map[string]error{"show clock": platform.ErrPromptTimeout})
	res, _ := runPartial(t, e, context.Background())
	if res.State != "partial" || st.count("show clock") != 1 {
		t.Fatalf("res = %+v ran=%v", res, st.ran)
	}
}

func TestCancelacionNoSeAnotaComoCorte(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	st := newCut(t, e, map[string]error{"show running-config": fmt.Errorf("%w: %w", platform.ErrPromptTimeout, context.Canceled)})
	ctx, cancel := context.WithCancel(context.Background())
	st.onCut = cancel
	res, _ := runPartial(t, e, ctx)
	if res.State != "failed" || len(res.CutCommands) != 0 {
		t.Fatalf("res = %+v", res)
	}
}
