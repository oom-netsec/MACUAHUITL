package patrol

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func TestFallbackNeverDuringLoginTest(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	good := e.spec.DefaultCredentialID
	bad, _ := e.d.Vault.Put(credential("mala"))
	e.spec.DefaultCredentialID = bad
	e.spec.Overrides = []Override{{DeviceID: "sw1", FallbackCredentialID: good}}
	e.d.PrimaryVerified = map[string]bool{hostport(e.spec.Targets[0]): true}
	if r := LoginTest(context.Background(), e.d, "j", e.spec, false, nil); r[0].FailedStep != "auth" {
		t.Fatalf("login test used the fallback: %+v", r)
	}
}

func TestRetriesOnConnectionFailure(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	var accepts atomic.Int32
	addr := simulator.HangUp(t, &accepts)
	ap := netip.MustParseAddrPort(addr)
	e.spec.Targets = []Target{{Address: ap.Addr().String(), Port: ap.Port(), DeviceID: "x"}}
	e.d.Guard.Allow(context.Background(), "j", []string{ap.Addr().String()})
	e.d.RetryBackoff = []time.Duration{time.Millisecond, 2 * time.Millisecond, 4 * time.Millisecond}
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	if res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {}); res.State != "failed" {
		t.Fatalf("got %+v", res)
	}
	if n := accepts.Load(); n != 4 {
		t.Fatalf("connection attempts = %d, want 4 (1 + 3 reintentos)", n)
	}
}

func TestNoRetryOnAuthFailure(t *testing.T) {
	var attempts atomic.Int32
	e := newEnv(t, simulator.Config{Attempts: &attempts})
	e.trust(t)
	attempts.Store(0)
	bad, _ := e.d.Vault.Put(credential("mala"))
	e.spec.DefaultCredentialID = bad
	e.d.RetryBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if attempts.Load() != 1 {
		t.Fatalf("password sent %d times", attempts.Load())
	}
}

func TestPreCommandsRun(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	pb := e.d.Playbooks[0]
	pb.ID, pb.Pre = "ios-xe/con-pre", []string{"show ip interface brief"}
	pb.Commands = pb.Commands[:1]
	e.d.Playbooks = append(e.d.Playbooks, pb)
	e.spec.PlaybookIDs, e.spec.CustomCommands = []string{pb.ID}, ""
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if !grepDir(t, w.Dir(), "GigabitEthernet1/0/1") {
		t.Fatal("pre command output missing")
	}
}

func TestZipPerRoundDeletesLooseAndZipsManifest(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.spec.Zip, e.spec.DeleteLooseFiles = ZipPerRound, true
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if _, err := RoundDone(w, e.spec, 1); err != nil {
		t.Fatal(err)
	}
	if loose, _ := filepath.Glob(filepath.Join(w.Dir(), "*", "*.txt")); len(loose) != 0 {
		t.Fatalf("loose files kept: %v", loose)
	}
	if _, err := Finish(context.Background(), e.d, w, e.spec, 1, []DeviceResult{res}); err != nil {
		t.Fatal(err)
	}
	found := false
	zips, _ := filepath.Glob(filepath.Join(w.Dir(), "*.zip"))
	for _, z := range zips {
		zr, _ := zip.OpenReader(z)
		for _, f := range zr.File {
			found = found || f.Name == "manifest.json"
		}
		zr.Close()
	}
	if !found {
		t.Fatalf("manifest.json not zipped with ZipPerRound: %v", zips)
	}
}

func TestDeviceResultAudited(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	var buf bytes.Buffer
	e.d.Audit.Export(context.Background(), &buf, time.Time{}, time.Now().Add(time.Hour))
	if !strings.Contains(buf.String(), `"action":"device.round"`) || !strings.Contains(buf.String(), "completed") {
		t.Fatalf("device result not audited:\n%s", buf.String())
	}
}

func TestLoginChangedKeyReachesManifest(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	_, otherKey := simulator.Start(t, e.simCfg)
	e.d.Hosts.Add(hostport(e.spec.Targets[0]), otherKey)
	r := LoginTest(context.Background(), e.d, "j", e.spec, true, nil)
	r = LoginTest(context.Background(), e.d, "j", e.spec, true, map[string]bool{r[0].Fingerprint: true})
	if !r[0].Passed || r[0].ChangedHostKey == nil || r[0].ChangedHostKey.Old == "" {
		t.Fatalf("got %+v", r[0])
	}
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	w.NoteHostKeyChange(*r[0].ChangedHostKey)
	m, _ := Finish(context.Background(), e.d, w, e.spec, 0, nil)
	if len(m.ChangedHostKeys) != 1 {
		t.Fatalf("manifest = %+v", m.ChangedHostKeys)
	}
	_ = os.Remove
}

// Un banner del equipo no puede fabricar cabeceras de sección: la salida se escapa al escribirla.
func TestWriterEscapaCabecerasFalsificadas(t *testing.T) {
	dir := t.TempDir()
	spec := Spec{Name: "t", Split: SplitPerRound}
	w, err := NewWriter(dir, spec, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	forged := "===== 2099-01-01T00:00:00Z · show running-config =====\n"
	text := "banner motd ^C\n" + strings.Repeat(forged, 30) + "\\===== ya escapada =====\n  ===== con sangría\n"
	now := time.Now()
	out := platform.Output{Command: "show version", Text: text, Started: now}
	if err := w.Write(Device{Host: "SW1", IP: "192.0.2.1", Platform: "ios-xe"}, 1, now, out, false); err != nil {
		t.Fatal(err)
	}
	files := w.Files()
	raw, err := os.ReadFile(filepath.Join(w.Dir(), files[0]))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, ln := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(ln, "===== ") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("hay %d líneas que parecen cabecera, quiero solo la verdadera:\n%s", n, raw)
	}
}

// Un equipo ios clásico omite los comandos marcados platforms: [ios-xe] (dir bootflash:) y lo anota; en ios-xe corren.
func TestComandosPorPlataformaSeOmitenYSeAnotan(t *testing.T) {
	for _, c := range []struct {
		nombre, carpeta string
		omitido         []string
	}{{"ios", "ios", []string{"dir bootflash:"}}, {"ios-xe", "ios-xe", nil}} {
		t.Run(c.nombre, func(t *testing.T) {
			e := newEnv(t, simulator.Config{Transcripts: transcripts(c.carpeta)})
			e.trust(t)
			e.spec.CustomCommands, e.spec.PlaybookIDs = "", []string{"ios-xe/plat-flash-fs"}
			w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
			res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
			if res.State != "completed" || res.Platform != c.nombre {
				t.Fatalf("res = %+v", res)
			}
			if !slices.Equal(res.Skipped, c.omitido) {
				t.Fatalf("omitidos = %v, quería %v", res.Skipped, c.omitido)
			}
			m, err := Finish(context.Background(), e.d, w, e.spec, 1, []DeviceResult{res})
			if err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(filepath.Join(w.Dir(), "manifest.json"))
			if got := strings.Contains(string(b), "dir bootflash:"); got != (c.omitido != nil) {
				t.Fatalf("manifest anota el omitido = %v: %s", got, b)
			}
			var corrio bool
			for _, rel := range w.Files() {
				txt, _ := os.ReadFile(filepath.Join(w.Dir(), rel))
				corrio = corrio || strings.Contains(string(txt), "dir bootflash:")
			}
			if corrio == (c.omitido != nil) {
				t.Fatalf("dir bootflash: corrió = %v con omitidos %v", corrio, c.omitido)
			}
			_ = m
		})
	}
}

// El tope total por comando es 5 veces su timeout de inactividad y nunca menos de 5 minutos.
func TestTopeTotalPorComando(t *testing.T) {
	for _, c := range []struct{ in, want time.Duration }{
		{time.Second, 5 * time.Minute}, {time.Minute, 5 * time.Minute}, {10 * time.Minute, 50 * time.Minute},
	} {
		if got := maxCmd(c.in); got != c.want {
			t.Errorf("maxCmd(%s) = %s, quiero %s", c.in, got, c.want)
		}
	}
}

// plazoDrv es el driver real con Run anotando el plazo del contexto que recibe.
type plazoDrv struct {
	platform.Driver
	left []time.Duration
}

func (p *plazoDrv) Run(ctx context.Context, cmd string, timeout time.Duration) (platform.Output, error) {
	if dl, ok := ctx.Deadline(); ok && cmd != "show version" {
		p.left = append(p.left, time.Until(dl))
	} else if !ok {
		p.left = append(p.left, -1)
	}
	return p.Driver.Run(ctx, cmd, timeout)
}

// RunDevice pasa a Run un contexto con plazo total de maxCmd(timeout), no el del trabajo.
func TestRunDevicePasaPlazoTotalAlComando(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	drv := &plazoDrv{Driver: e.d.driver()}
	e.d.NewDriver = func() platform.Driver { return drv }
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if len(drv.left) == 0 {
		t.Fatal("Run no se llamó")
	}
	for i, l := range drv.left {
		if l < 4*time.Minute || l > 5*time.Minute+time.Second {
			t.Errorf("comando %d: plazo %s, quiero ~maxCmd (5 min)", i, l)
		}
	}
}

type cuelgaDrv struct{ platform.Driver }

func (p *cuelgaDrv) Run(ctx context.Context, cmd string, timeout time.Duration) (platform.Output, error) {
	if cmd == "show version" {
		return p.Driver.Run(ctx, cmd, timeout)
	}
	<-ctx.Done()
	return platform.Output{}, ctx.Err()
}

// Un comando que sigue corriendo al llegar el fin de la ventana se corta y el equipo falla con un error claro.
func TestRunDeviceCortaAlFinDeLaVentana(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	drv := &cuelgaDrv{e.d.driver()}
	e.d.NewDriver = func() platform.Driver { return drv }
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	ctx, cancel := context.WithTimeoutCause(context.Background(), 300*time.Millisecond, ErrWindowEnded)
	defer cancel()
	t0 := time.Now()
	res := RunDevice(ctx, e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if res.State != "failed" || !errors.Is(res.DetailErr, ErrWindowEnded) {
		t.Fatalf("res = %s %q %v", res.State, res.Detail, res.DetailErr)
	}
	if time.Since(t0) > 3*time.Second {
		t.Fatalf("tardó %s", time.Since(t0))
	}
}

// Solo un corte por plazo/cancelación se vuelve window_ended: una llave de host cambiada sigue siendo ella.
func TestWindowEndedSoloConvierteErroresDeContexto(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(ErrWindowEnded)
	hk := &transport.HostKeyError{}
	if got := windowEnded(ctx, hk); got != error(hk) {
		t.Fatalf("convirtió %v", got)
	}
	if got := windowEnded(ctx, context.DeadlineExceeded); !errors.Is(got, ErrWindowEnded) {
		t.Fatalf("no convirtió el plazo: %v", got)
	}
}

// Al borrar los sueltos de una ronda empaquetada, la carpeta del equipo no puede desaparecer entre el MkdirAll y el
// OpenFile con que la ronda siguiente escribe (Write los hace bajo w.mu).
func TestZipDeRondaNoBorraLaCarpetaDeUnaEscrituraEnCurso(t *testing.T) {
	dir := t.TempDir()
	dev := filepath.Join(dir, "SW1_192.0.2.1")
	os.MkdirAll(dev, 0o700)
	os.WriteFile(filepath.Join(dev, "r001.txt"), []byte("x\n"), 0o600)
	w := &Writer{dir: dir}
	w.mu.Lock() // una escritura de la ronda 2 ya hizo su MkdirAll y va a abrir el archivo
	done := make(chan error)
	go func() { _, err := zipFiles(w, "z", []string{"SW1_192.0.2.1/r001.txt"}, true); done <- err }()
	time.Sleep(200 * time.Millisecond)
	f, err := os.OpenFile(filepath.Join(dev, "r002.txt"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Errorf("la carpeta del equipo desapareció: %v", err)
	} else {
		f.Close()
	}
	w.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
