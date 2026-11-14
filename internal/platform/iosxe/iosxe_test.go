package iosxe

import (
	"context"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func dir(p string) string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "..", "test", "transcripts", p)
}

func open(t *testing.T, c simulator.Config, enable string, ctx context.Context) (platform.Driver, error) {
	t.Helper()
	if c.Hostname == "" {
		c.Hostname = "SW1"
	}
	c.Username, c.Password = "admin", "pw"
	if c.Enable == "" {
		c.Enable = "en"
	}
	if c.Transcripts == "" {
		c.Transcripts = dir("ios-xe")
	}
	addr, hk := simulator.Start(t, c)
	ap := netip.MustParseAddrPort(addr)
	g := transport.NewGuard(nil, nil)
	g.Allow(context.Background(), "j", []string{ap.Addr().String()})
	cred := vault.Credential{Username: "admin", Password: secret.New([]byte("pw"))}
	s, err := transport.OpenSSH(context.Background(), g, "j", ap.Addr().String(), ap.Port(), cred, simulator.TrustKey(hk), transport.SSHOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	r, w, err := s.Shell()
	if err != nil {
		t.Fatal(err)
	}
	d := New()
	return d, d.Open(ctx, r, w, secret.New([]byte(enable)))
}

func transcript(t *testing.T, platformDir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir(platformDir), name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitN(string(b), "\n", 2)[1]
}

func TestOpenEnableAndRun(t *testing.T) {
	d, err := open(t, simulator.Config{}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show version", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != transcript(t, "ios-xe", "show_version.txt") {
		t.Fatalf("text mismatch:\n%q", out.Text)
	}
	if out.Invalid || out.Command != "show version" || out.Ended.Before(out.Started) {
		t.Fatalf("output = %+v", out)
	}
}

func TestDetectIOSXE(t *testing.T) {
	d, err := open(t, simulator.Config{}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname() != "SW1" {
		t.Fatalf("Hostname = %q", d.Hostname())
	}
	if p, err := d.Detect(context.Background()); err != nil || p != "ios-xe" {
		t.Fatalf("Detect = %q, %v", p, err)
	}
}

func TestDetectIOS(t *testing.T) {
	d, err := open(t, simulator.Config{Transcripts: dir("ios")}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p, err := d.Detect(context.Background()); err != nil || p != "ios" {
		t.Fatalf("Detect = %q, %v", p, err)
	}
}

func TestInvalidCommand(t *testing.T) {
	d, err := open(t, simulator.Config{}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show nada", 5*time.Second)
	if err != nil || !out.Invalid {
		t.Fatalf("out = %+v, %v", out, err)
	}
}

func TestPagingFallback(t *testing.T) {
	d, err := open(t, simulator.Config{IgnoreTerminalLength: true}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show running-config", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != transcript(t, "ios-xe", "show_running-config.txt") {
		t.Fatalf("paged output mismatch (len %d)", len(out.Text))
	}
}

func TestPromptTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := open(t, simulator.Config{HangAfterLogin: true}, "en", ctx)
	if !errors.Is(err, platform.ErrPromptTimeout) || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
}

func TestEnableFailed(t *testing.T) {
	_, err := open(t, simulator.Config{}, "mala", context.Background())
	if !errors.Is(err, platform.ErrEnableFailed) {
		t.Fatalf("err = %v", err)
	}
}

func TestAlreadyPrivileged(t *testing.T) {
	d, err := open(t, simulator.Config{StartPrivileged: true}, "", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Run(context.Background(), "show version", 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestDropDuringCommand(t *testing.T) {
	d, err := open(t, simulator.Config{DropDuringCommand: "show running-config"}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show running-config", 5*time.Second)
	if err == nil || out.Text == "" {
		t.Fatalf("want error with partial output, got %v / %d bytes", err, len(out.Text))
	}
}

func TestCommandTimeout(t *testing.T) {
	d, err := open(t, simulator.Config{SlowCommand: "show lento", SlowDelay: time.Second}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Run(context.Background(), "show lento", 200*time.Millisecond); !errors.Is(err, platform.ErrPromptTimeout) {
		t.Fatalf("err = %v", err)
	}
}

func TestCleanEraseSequences(t *testing.T) {
	in := "a\r\n --More-- \r          \rb\r\n --More-- \x08\x08\x08\x08   \x08\x08\x08\x08c\r\n"
	if got := clean(in); got != "a\nb\nc\n" {
		t.Fatalf("clean = %q", got)
	}
}

// Una salida grande y lenta (show memory summary en un 3560CX) que sigue llegando no se corta por el plazo: el
// plazo es de inactividad. Mientras llegan líneas, el comando sigue.
func TestPlazoEsDeInactividad(t *testing.T) {
	d, err := open(t, simulator.Config{StreamCommand: "show memory summary", StreamLines: 20, SlowDelay: 50 * time.Millisecond}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show memory summary", 300*time.Millisecond)
	if err != nil || strings.Count(out.Text, "\n") != 20 || !strings.Contains(out.Text, "linea 20 de") {
		t.Fatalf("err = %v, salida %q", err, out.Text)
	}
}

// Aun con datos llegando (cada 20 ms, menos que el plazo de inactividad), ningún comando corre más que maxRun.
func TestTopeAbsolutoDelComando(t *testing.T) {
	old := maxRun
	maxRun = 400 * time.Millisecond
	defer func() { maxRun = old }()
	d, err := open(t, simulator.Config{StreamCommand: "show sin fin", StreamLines: 1000, SlowDelay: 20 * time.Millisecond}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now() // inactividad de 10 s: solo el tope puede cortar antes de 2 s
	if _, err := d.Run(context.Background(), "show sin fin", 10*time.Second); !errors.Is(err, platform.ErrPromptTimeout) || time.Since(start) < maxRun || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v tras %s", err, time.Since(start))
	}
}

// Con una salida de 1 MB (show tech), el prompt y el --More-- se buscan solo en la última línea: revisar todo el
// búfer en cada pedazo costaba tiempo cuadrático. La salida devuelta sigue completa y limpia.
func TestSalidaGrandeSoloRevisaLaCola(t *testing.T) {
	d := &driver{w: io.Discard, chunks: make(chan []byte, 2000), readErr: make(chan error, 1), quit: make(chan struct{}), hostname: "SW"}
	line := strings.Repeat("x", 1000) + "\r\n"
	for range 1000 {
		d.chunks <- []byte(line)
	}
	d.chunks <- []byte(" --More-- ")
	d.chunks <- []byte("\r          \rfin\r\nSW#")
	maxArg := 0
	text, err := d.untilIdle(context.Background(), time.Second, func(s string) bool {
		maxArg = max(maxArg, len(s))
		return d.atPrompt(s)
	})
	if err != nil {
		t.Fatal(err)
	}
	if maxArg > 2048 {
		t.Errorf("done recibió %d bytes: revisa todo el búfer, no la cola", maxArg)
	}
	if want := strings.Repeat(strings.Repeat("x", 1000)+"\n", 1000) + "fin\nSW#"; text != want {
		t.Errorf("salida: %d bytes, quiero %d", len(text), len(want))
	}
}

// Si al vencer el plazo el canal de pedazos ya está cerrado, el error es el cierre de la sesión, no un timeout.
// Con ambos casos listos el select elige al azar, por eso se repite.
func TestPlazoConCanalCerradoDaErrClosed(t *testing.T) {
	for range 200 {
		d := &driver{w: io.Discard, chunks: make(chan []byte), readErr: make(chan error, 1), quit: make(chan struct{}), hostname: "SW"}
		d.readErr <- io.EOF
		close(d.chunks)
		_, err := d.untilIdle(context.Background(), time.Nanosecond, func(string) bool { return false })
		if !errors.Is(err, platform.ErrClosed) {
			t.Fatalf("err = %v, quiero ErrClosed", err)
		}
	}
}

// Detect tiene tope total: un "show version" a goteo no lo retiene más que maxDetect.
func TestDetectTieneTopeTotal(t *testing.T) {
	old := maxDetect
	maxDetect = 400 * time.Millisecond
	defer func() { maxDetect = old }()
	d, err := open(t, simulator.Config{StreamCommand: "show version", StreamLines: 1000, SlowDelay: 20 * time.Millisecond}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := d.Detect(context.Background()); !errors.Is(err, platform.ErrPromptTimeout) || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v tras %s", err, time.Since(start))
	}
}

// Fixtures de la documentación de Cisco (9800-CL y EWC en AP), sin validar en laboratorio.
func TestDetectWLC9800(t *testing.T) {
	for _, f := range []string{"wlc-9800-cl", "wlc-9800-ewc"} {
		d, err := open(t, simulator.Config{Transcripts: dir(f)}, "en", context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if p, err := d.Detect(context.Background()); err != nil || p != "wlc-9800" {
			t.Fatalf("%s: Detect = %q, %v", f, p, err)
		}
	}
}

// Un Catalyst 9300 cuyo hostname lleva «C9800» sigue siendo ios-xe: la marca se busca en la línea del software.
func TestDetectHostnameC9800NoEsWLC(t *testing.T) {
	tmp := t.TempDir()
	for _, n := range []string{"show_version.txt", "show_ip_interface_brief.txt", "show_running-config.txt"} {
		b, err := os.ReadFile(filepath.Join(dir("ios-xe"), n))
		if err != nil {
			t.Fatal(err)
		}
		b = []byte(strings.ReplaceAll(string(b), "SW-LAB-01", "SW-C9800-UPLINK"))
		if err := os.WriteFile(filepath.Join(tmp, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := open(t, simulator.Config{Transcripts: tmp}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p, err := d.Detect(context.Background()); err != nil || p != "ios-xe" {
		t.Fatalf("Detect = %q, %v", p, err)
	}
}

// Al cancelarse o vencer el contexto, el error conserva su causa para que Patrol distinga el fin de la ventana.
func TestCancelarComandoConservaLaCausa(t *testing.T) {
	d, err := open(t, simulator.Config{StreamCommand: "show sin fin", StreamLines: 1000, SlowDelay: 20 * time.Millisecond}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := d.Run(ctx, "show sin fin", 10*time.Second); !errors.Is(err, platform.ErrPromptTimeout) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

// Fixtures de show version de N9K y N7K de la documentación de Cisco, sin validar en laboratorio.
func TestDetectNXOS(t *testing.T) {
	for _, f := range []string{"nx-os-n9k", "nx-os-n7k"} {
		d, err := open(t, simulator.Config{Transcripts: dir(f), StartPrivileged: true}, "", context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if p, err := d.Detect(context.Background()); err != nil || p != "nx-os" {
			t.Fatalf("%s: Detect = %q, %v", f, p, err)
		}
	}
}

// Un IOS-XE que menciona «NX-OS» en texto libre no es un Nexus: solo cuenta la línea de cabecera.
func TestDetectMencionNXOSNoEsNexus(t *testing.T) {
	tmp := t.TempDir()
	b, err := os.ReadFile(filepath.Join(dir("ios-xe"), "show_version.txt"))
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, []byte("\nmigrated from Cisco Nexus Operating System (NX-OS) Software box\n")...)
	if err := os.WriteFile(filepath.Join(tmp, "show_version.txt"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := open(t, simulator.Config{Transcripts: tmp}, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if p, err := d.Detect(context.Background()); err != nil || p != "ios-xe" {
		t.Fatalf("Detect = %q, %v", p, err)
	}
}

// fakeNX es un equipo mínimo que contesta línea por línea y anota lo recibido.
func fakeNX(t *testing.T, rejectWidth0 bool) (*driver, *[]string) {
	t.Helper()
	devR, drvW := io.Pipe()
	drvR, devW := io.Pipe()
	var got []string
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.WriteString(devW, "N9K# ")
		buf := make([]byte, 0, 256)
		b := make([]byte, 1)
		for {
			if _, err := devR.Read(b); err != nil {
				return
			}
			if b[0] != '\n' {
				buf = append(buf, b[0])
				continue
			}
			line := string(buf)
			buf = buf[:0]
			got = append(got, line)
			out := line + "\r\n"
			if line == "terminal width 0" && rejectWidth0 {
				out += "% Invalid input detected at '^' marker.\r\n"
			}
			io.WriteString(devW, out+"N9K# ")
		}
	}()
	t.Cleanup(func() { drvW.Close(); devW.Close(); <-done })
	d := New().(*driver)
	if err := d.Open(context.Background(), drvR, drvW, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	return d, &got
}

// NX-OS no tiene enable y su ancho máximo es 511: solo si rechazó «terminal width 0» se manda 511.
func TestAnchoNXOSSoloSiRechazaCero(t *testing.T) {
	_, got := fakeNX(t, true)
	if want := []string{"terminal length 0", "terminal width 0", "terminal width 511"}; !slices.Equal(*got, want) {
		t.Fatalf("rechazado: %q", *got)
	}
	_, got = fakeNX(t, false)
	if want := []string{"terminal length 0", "terminal width 0"}; !slices.Equal(*got, want) {
		t.Fatalf("aceptado: %q", *got)
	}
}
