package iosxe

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

// fakeDev es un equipo mínimo línea por línea: reply recibe cada línea y devuelve lo que imprime antes del prompt.
// Anota todo lo que el driver escribe (bytes, no solo líneas completas).
type fakeDev struct {
	mu      sync.Mutex
	wrote   []byte
	onSpace string // lo que imprime al recibir un espacio suelto (respuesta a --More--)
}

func (f *fakeDev) written() string { f.mu.Lock(); defer f.mu.Unlock(); return string(f.wrote) }

// startFake arranca el equipo; first es lo primero que imprime (prompt incluido) y prompt el que sigue a cada respuesta.
func startFake(t *testing.T, first, prompt string, reply func(line string) (out string, newPrompt string)) (*fakeDev, io.Reader, io.Writer) {
	t.Helper()
	devR, drvW := io.Pipe()
	drvR, devW := io.Pipe()
	f := &fakeDev{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.WriteString(devW, first)
		var buf []byte
		b := make([]byte, 1)
		for {
			if n, err := devR.Read(b); err != nil {
				return
			} else if n == 0 { // una escritura de 0 bytes no repite el byte anterior
				continue
			}
			f.mu.Lock()
			f.wrote = append(f.wrote, b[0])
			sp := f.onSpace
			if b[0] == ' ' && len(buf) == 0 && sp != "" {
				f.onSpace = ""
			}
			f.mu.Unlock()
			if b[0] == ' ' && len(buf) == 0 && sp != "" {
				io.WriteString(devW, sp+prompt)
				continue
			}
			if b[0] != '\n' {
				buf = append(buf, b[0])
				continue
			}
			line := string(buf)
			buf = buf[:0]
			out, np := reply(line)
			if np != "" && np != "-" {
				prompt = np
			}
			if np == "-" { // el equipo espera algo (contraseña, espacio) en vez de mostrar el prompt
				io.WriteString(devW, line+"\r\n"+out)
				continue
			}
			io.WriteString(devW, line+"\r\n"+out+prompt)
		}
	}()
	t.Cleanup(func() { drvW.Close(); devW.Close(); <-done })
	return f, drvR, drvW
}

func asaVersion(t *testing.T, dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "show_version.txt"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitN(string(b), "\n", 2)[1]
}

// Fixtures de show version de ASAv y 5516-X armadas con la forma de la documentación de Cisco, sin validar en laboratorio.
func TestDetectASA(t *testing.T) {
	for _, f := range []string{"asa-asav", "asa-5516x"} {
		d, err := open(t, simulator.Config{Transcripts: dir(f), StartPrivileged: true, Hostname: "ciscoasa"}, "", context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if p, err := d.Detect(context.Background()); err != nil || p != "asa" {
			t.Fatalf("%s: Detect = %q, %v", f, p, err)
		}
	}
}

// Un IOS-XE que dice «Adaptive Security» en texto libre no es un ASA: cuenta solo la línea de cabecera.
func TestDetectMencionASANoEsASA(t *testing.T) {
	tmp := t.TempDir()
	b, err := os.ReadFile(filepath.Join(dir("ios-xe"), "show_version.txt"))
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, []byte("\nmigrated from Cisco Adaptive Security Appliance Software Version 9.14(4) box\n")...)
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

func asaReply(rejectLength bool) func(string) (string, string) {
	return func(line string) (string, string) {
		switch {
		case line == "terminal length 0" && rejectLength:
			return "ERROR: % Invalid input detected at '^' marker.\r\n", ""
		case line == "terminal width 0":
			return "ERROR: % Invalid input detected at '^' marker.\r\n", ""
		case line == "show nada":
			return "ERROR: % Invalid input detected at '^' marker.\r\n", ""
		}
		return "", ""
	}
}

func lines(s string) []string { return strings.Split(strings.TrimSuffix(s, "\n"), "\n") }

// ASA no admite «terminal length 0» (usa «terminal pager 0») ni ancho 0: «ERROR: %» cuenta como rechazo.
func TestASAPaginacionYAncho(t *testing.T) {
	f, r, w := startFake(t, "asa# ", "asa# ", asaReply(true))
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	got := lines(f.written())
	want := []string{"terminal length 0", "terminal pager 0", "terminal width 0", "terminal width 511"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("enviado %q", got)
	}
	// si length 0 se acepta no se manda pager
	f, r, w = startFake(t, "asa# ", "asa# ", asaReply(false))
	d = New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.written(), "pager") {
		t.Fatalf("pager sin necesitarlo: %q", f.written())
	}
}

func TestASAErrorCuentaComoInvalido(t *testing.T) {
	_, r, w := startFake(t, "asa# ", "asa# ", asaReply(false))
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show nada", 5*time.Second)
	if err != nil || !out.Invalid {
		t.Fatalf("out = %+v, %v", out, err)
	}
	if !hasPercentLine("ERROR: % Invalid input\n") || hasPercentLine("ERROR: algo sin porcentaje\n") {
		t.Error("hasPercentLine con ERROR: %")
	}
}

// «<--- More --->» de ASA se responde con espacio y no queda en la salida.
func TestASAMore(t *testing.T) {
	f, r, w := startFake(t, "asa# ", "asa# ", func(line string) (string, string) {
		if line == "show run" {
			return "uno\r\n<--- More --->", "-"
		}
		return "", ""
	})
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.onSpace = "\r        \r\r\ndos\r\n"
	f.mu.Unlock()
	out, err := d.Run(context.Background(), "show run", 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out.Text != "uno\n\ndos\n" && out.Text != "uno\ndos\n" {
		t.Fatalf("texto %q", out.Text)
	}
}

// Enable sin clave fijada (ASA 9.12+): el driver NO escribe nada tras «enable»: mandar el secreto fijaría la clave.
func TestASAEnableSinClaveNoEscribeNada(t *testing.T) {
	for _, prompt := range []string{
		"The enable password is not set. Please set it now.\r\nEnter  Password: ",
		"The enable password is not set. Please set it now.\r\nRepeat Password: ",
		"Enter  Password: ",
		"Repeat Password: ",
	} {
		f, r, w := startFake(t, "asa> ", "asa> ", func(line string) (string, string) {
			if line == "enable" {
				return prompt, "-"
			}
			return "", ""
		})
		d := New().(*driver)
		err := d.Open(context.Background(), r, w, secret.New([]byte("en")))
		if !errors.Is(err, platform.ErrEnableFailed) {
			t.Fatalf("%q: Open = %v", prompt, err)
		}
		if got := f.written(); got != "enable\n" {
			t.Fatalf("%q: se escribió %q tras el prompt", prompt, got)
		}
	}
}

// El «Password:» normal del enable sigue funcionando con secreto.
func TestASAEnableConClave(t *testing.T) {
	f, r, w := startFake(t, "asa> ", "asa> ", func(line string) (string, string) {
		switch line {
		case "enable":
			return "Password: ", "-"
		case "en":
			return "", "asa# "
		}
		return "", ""
	})
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New([]byte("en"))); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(f.written(), "enable\nen\n") {
		t.Fatalf("se escribió %q", f.written())
	}
}

// Prompt multicontexto: «asa/admin#» y «asa/pri/act#» (prompt hostname priority state).
func TestASAPromptMulticontexto(t *testing.T) {
	for _, p := range []string{"asa/admin", "asa/pri/act", "asa/sec/stby"} {
		_, r, w := startFake(t, p+"# ", p+"# ", func(line string) (string, string) {
			if line == "show clock" {
				return "10:00:00.000 UTC Mon Nov 3 2026\r\n", ""
			}
			return "", ""
		})
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if d.Hostname() != p {
			t.Fatalf("Hostname = %q", d.Hostname())
		}
		out, err := d.Run(context.Background(), "show clock", 5*time.Second)
		if err != nil || out.Text != "10:00:00.000 UTC Mon Nov 3 2026\n" {
			t.Fatalf("%s: out = %q, %v", p, out.Text, err)
		}
	}
}

// Ninguna ruta del driver (Open, Run, Detect) manda «configure terminal» a un ASA.
func TestASANuncaMandaConfigure(t *testing.T) {
	ver := asaVersion(t, dir("asa-asav"))
	f, r, w := startFake(t, "asa> ", "asa> ", func(line string) (string, string) {
		switch line {
		case "enable":
			return "Password: ", "-"
		case "en":
			return "", "asa# "
		case "show version":
			return strings.ReplaceAll(ver, "\n", "\r\n"), ""
		}
		return "", ""
	})
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New([]byte("en"))); err != nil {
		t.Fatal(err)
	}
	if p, err := d.Detect(context.Background()); err != nil || p != "asa" {
		t.Fatalf("Detect = %q, %v", p, err)
	}
	if _, err := d.Run(context.Background(), "show clock", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := f.written(); strings.Contains(got, "configure") || strings.Contains(got, "conf t") {
		t.Fatalf("se escribió %q", got)
	}
}

// Primer inicio de sesión de un usuario nuevo del ASA 9.x (visto en CML): pide cambiar la contraseña. El driver aborta
// al instante con ErrFirstLogin, sin escribir nada y antes de saber la plataforma (antes esperaba el prompt hasta el
// timeout y el Login Test decía «the device did not show a prompt in time»).
func TestASAPrimerLoginNoEscribeNada(t *testing.T) {
	fastSettle(t)
	for _, first := range []string{
		"This is your first login. Please set a new password before proceeding.\r\nEnter old password: ",
		"This is your first login.",
		"Please set a new password before proceeding.",
		"Enter old password:",
	} {
		f, r, w := startFake(t, first, "asa# ", asaReply(true))
		d := New().(*driver)
		start := time.Now()
		err := d.Open(context.Background(), r, w, secret.New([]byte("en")))
		if !errors.Is(err, platform.ErrFirstLogin) {
			t.Fatalf("%q: Open = %v", first, err)
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("%q: tardó %v (esperó el timeout)", first, time.Since(start))
		}
		time.Sleep(20 * time.Millisecond)
		if got := f.written(); got != "" {
			t.Fatalf("%q: se escribió %q", first, got)
		}
	}
}

// Un banner que cita la frase y sigue (llega antes que el prompt) no es un primer login: el ancla al final del búfer lo
// distingue, y el prompt que llega después abre la sesión normal.
func TestASABannerQueCitaElPrimerLoginNoEsPrimerLogin(t *testing.T) {
	got, err := openBanner(t, "asa# ", false, "\r\nAviso: This is your first login? No, see policy.", 2*ftdSettle, "\r\nasa# ")
	if err != nil || got != abre {
		t.Fatalf("Open = %v, escrito %q", err, got)
	}
}
