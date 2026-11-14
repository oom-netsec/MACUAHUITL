package iosxe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

const aireP = "(Cisco Controller) >"

// Salida de «show sysinfo» armada con la forma de la Command Reference 8.10, sin validar en laboratorio.
const aireSysinfoOut = "\r\nManufacturer's Name.............................. Cisco Systems Inc.\r\nProduct Name..................................... Cisco Controller\r\nProduct Version.................................. 8.10.185.0\r\n"

func aireReply(line string) (string, string) {
	switch line {
	case "show sysinfo":
		return aireSysinfoOut, ""
	case "show version":
		return "Incorrect usage.\r\n", ""
	}
	return "", ""
}

func openAire(t *testing.T, first string, reply func(string) (string, string), user, pw string) (*fakeDev, *driver, error) {
	t.Helper()
	f, r, w := startFake(t, first, aireP, reply)
	d := New().(*driver)
	if user != "" || pw != "" {
		d.SetLogin(user, secret.New([]byte(pw)))
	}
	return f, d, d.Open(context.Background(), r, w, secret.New([]byte("en")))
}

// Prompt «(Nombre) >»: el nombre es lo que va entre paréntesis (con espacios); sin enable ni «terminal …» (config paging
// disable es configuración); Open no escribe nada. Detect usa show sysinfo y nunca manda show version.
func TestAireOSOpenYDetect(t *testing.T) {
	f, d, err := openAire(t, "\r\n(Cisco Controller) >", aireReply, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if d.Hostname() != "Cisco Controller" {
		t.Fatalf("Hostname = %q", d.Hostname())
	}
	if p, err := d.Detect(context.Background()); err != nil || p != "wlc-aireos" {
		t.Fatalf("Detect = %q, %v", p, err)
	}
	if got := f.written(); got != "show sysinfo\n" {
		t.Fatalf("escrito %q", got)
	}
}

func TestAireOSDetectNoEsAireOS(t *testing.T) {
	_, d, err := openAire(t, aireP, func(l string) (string, string) {
		if l == "show sysinfo" {
			return "Product Name..................................... Otra cosa\r\n", ""
		}
		return "", ""
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Detect(context.Background()); !errors.Is(err, platform.ErrUnknownPlatform) {
		t.Fatalf("Detect = %v", err)
	}
}

// El prompt de configuración «(X) config>» no es de lectura: el driver nunca entra a config; si aparece, es error.
func TestAireOSPromptDeConfiguracionEsError(t *testing.T) {
	f, r, w := startFake(t, "(Cisco Controller) config>", aireP, aireReply)
	d := New().(*driver)
	err := d.Open(context.Background(), r, w, secret.New(nil))
	if !errors.Is(err, platform.ErrConfigPrompt) || f.written() != "" {
		t.Fatalf("Open = %v, escrito %q", err, f.written())
	}
	_, d, err = openAire(t, "(Cisco Controller) >", func(l string) (string, string) {
		if l == "show x" {
			return "", "(Cisco Controller) config>"
		}
		return "", ""
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Run(context.Background(), "show x", 2*time.Second); !errors.Is(err, platform.ErrConfigPrompt) {
		t.Fatalf("Run = %v", err)
	}
}

func loginReply(pw, after string) func(string) (string, string) {
	return func(line string) (string, string) {
		switch line {
		case "admin":
			return "", "Password: "
		case pw:
			return after, aireP
		}
		return aireReply(line)
	}
}

// Doble autenticación: «User:» y «Password:» antes del primer prompt. Se escribe usuario y clave, una vez, nada más.
func TestAireOSLoginEnElShell(t *testing.T) {
	f, d, err := openAire(t, "\r\n(Cisco Controller) \r\nUser: ", loginReply("s3cret", ""), "admin", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if got := f.written(); got != "admin\ns3cret\n" {
		t.Fatalf("escrito %q", got)
	}
	if d.Hostname() != "Cisco Controller" || d.login != nil {
		t.Fatalf("Hostname %q, login %v", d.Hostname(), d.login)
	}
	// «User:» y «Username:»
	f, _, err = openAire(t, "Username: ", loginReply("s3cret", ""), "admin", "s3cret")
	if err != nil || f.written() != "admin\ns3cret\n" {
		t.Fatalf("Username: %v, escrito %q", err, f.written())
	}
}

// Rechazo (vuelve a pedir User: o Password:), sin credencial o sin usuario: se aborta sin reintentar y sin escribir de más.
func TestAireOSLoginRechazoYSinCredencial(t *testing.T) {
	for name, tc := range map[string]struct {
		first, user, pw string
		reply           func(string) (string, string)
		want            string
	}{
		"rechazo con User:": {"User: ", "admin", "s3cret", func(l string) (string, string) {
			if l == "admin" {
				return "", "Password: "
			}
			return "\r\nAuthentication failed\r\n", "User: "
		}, "admin\ns3cret\n"},
		"rechazo con Password:": {"User: ", "admin", "s3cret", func(l string) (string, string) { return "", "Password: " }, "admin\ns3cret\n"},
		"sin credencial":        {"User: ", "", "", loginReply("x", ""), ""},
		"sin usuario":           {"User: ", "", "s3cret", loginReply("x", ""), ""},
		"sin clave":             {"User: ", "admin", "", loginReply("x", ""), ""},
	} {
		f, _, err := openAire(t, tc.first, tc.reply, tc.user, tc.pw)
		if !errors.Is(err, platform.ErrLoginFailed) {
			t.Errorf("%s: Open = %v", name, err)
		}
		time.Sleep(20 * time.Millisecond)
		if got := f.written(); got != tc.want {
			t.Errorf("%s: escrito %q, se esperaba %q", name, got, tc.want)
		}
	}
}

// La clave no sale en el error de login, ni en sus textos es/en, ni en los logs, aunque el equipo la repita con eco.
func TestAireOSLaClaveNoSaleEnErrorNiLogs(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	const pw = "Cl4v3-Sup3r-S3cr3ta"
	_, d, err := openAire(t, "User: ", func(l string) (string, string) {
		if l == "admin" {
			return "", "Password: "
		}
		return "Login failed for " + l + "\r\n", "User: " // el eco de la clave ya viene en la línea del fake
	}, "admin", pw)
	if !errors.Is(err, platform.ErrLoginFailed) {
		t.Fatalf("Open = %v", err)
	}
	for _, s := range []string{err.Error(), fmt.Sprintf("%v|%+v|%#v", err, err, err), i18n.In("es", err), i18n.In("en", err), logs.String()} {
		if strings.Contains(s, pw) {
			t.Fatalf("la clave aparece en %q", s)
		}
	}
	if strings.Contains(string(d.buf), pw) || d.login != nil {
		t.Fatalf("la clave quedó en el driver: buf=%q login=%v", d.buf, d.login)
	}
}

// La clave clonada se destruye al terminar Open (la use o no) y en Close; la original no se toca.
func TestAireOSCloseDestruyeLaClave(t *testing.T) {
	d := New().(*driver)
	orig := secret.New([]byte("s3cret"))
	d.SetLogin("admin", orig)
	cl := d.login
	if cl == orig || string(cl.Bytes()) != "s3cret" {
		t.Fatal("no clonó")
	}
	d.Close() // sin Open
	if !cl.Empty() || orig.Empty() {
		t.Fatalf("Close: clon vacío=%v, original vacío=%v", cl.Empty(), orig.Empty())
	}
	_, r, w := startFake(t, aireP, aireP, aireReply)
	d = New().(*driver)
	d.SetLogin("admin", orig)
	cl = d.login
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if !cl.Empty() || orig.Empty() {
		t.Fatalf("Open sin login: clon vacío=%v, original vacío=%v", cl.Empty(), orig.Empty())
	}
}

// «User:» o «Password:» después del primer prompt, o por segunda vez: se aborta sin escribir.
func TestAireOSLoginTardioNoEscribe(t *testing.T) {
	f, d, err := openAire(t, aireP, func(l string) (string, string) {
		if l == "show x" {
			return "", "User: "
		}
		return "", ""
	}, "admin", "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if f.written() != "" {
		t.Fatalf("Open escribió %q con prompt directo", f.written())
	}
	if _, err := d.Run(context.Background(), "show x", 2*time.Second); !errors.Is(err, platform.ErrLoginFailed) {
		t.Fatalf("Run = %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if got := f.written(); got != "show x\n" {
		t.Fatalf("escrito %q", got)
	}
	if _, err := d.Run(context.Background(), "show y", time.Second); err == nil || f.written() != "show x\n" {
		t.Fatalf("sesión inservible: %v, escrito %q", err, f.written())
	}
	// Password: suelto a mitad de sesión
	f, d, _ = openAire(t, aireP, func(l string) (string, string) { return "", "Password: " }, "admin", "s3cret")
	if _, err := d.Run(context.Background(), "show x", 2*time.Second); !errors.Is(err, platform.ErrLoginFailed) || f.written() != "show x\n" {
		t.Fatalf("Password: %v, escrito %q", err, f.written())
	}
}

// pagedDev reparte páginas con «--More-- or (q)uit»; cada página se parte en dos escrituras en cut (con pausa).
func pagedDev(t *testing.T, pages []string, cut func(page string) int) (io.Reader, io.Writer, func() string) {
	devR, drvW := io.Pipe()
	drvR, devW := io.Pipe()
	var mu sync.Mutex
	var wrote []byte
	t.Cleanup(func() { drvW.Close(); devW.Close() })
	send := func(s string) {
		if c := cut(s); c > 0 && c < len(s) {
			io.WriteString(devW, s[:c])
			time.Sleep(15 * time.Millisecond)
			s = s[c:]
		}
		io.WriteString(devW, s)
	}
	go func() {
		io.WriteString(devW, aireP)
		var line []byte
		next := 0
		b := make([]byte, 1)
		for {
			if _, err := devR.Read(b); err != nil {
				return
			}
			mu.Lock()
			wrote = append(wrote, b[0])
			mu.Unlock()
			switch {
			case b[0] == ' ' && len(line) == 0 && next > 0 && next < len(pages):
				send("\r                  \r" + pages[next])
				next++
			case b[0] == '\n':
				if string(line) == "show ap summary" {
					send("show ap summary\r\n" + pages[0])
					next = 1
				}
				line = line[:0]
			default:
				line = append(line, b[0])
			}
		}
	}()
	return drvR, drvW, func() string { mu.Lock(); defer mu.Unlock(); return string(wrote) }
}

// --More-- or (q)uit se contesta con un espacio por página (varias seguidas, también con un usuario sin permiso de
// config paging), se borra de la salida y no se confunde cuando llega partido entre dos lecturas.
func TestAireOSPaginacion(t *testing.T) {
	pages := []string{"a1\r\na2\r\n--More-- or (q)uit", "a3\r\na4\r\n--More-- or (q)uit", "a5\r\n\r\n" + aireP}
	for off := -1; off <= len("--More-- or (q)uit"); off++ {
		r, w, written := pagedDev(t, pages, func(p string) int {
			i := strings.Index(p, "--More--")
			if off < 0 || i < 0 {
				return 0
			}
			return i + off
		})
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatal(err)
		}
		out, err := d.Run(context.Background(), "show ap summary", 2*time.Second)
		if err != nil || strings.Join(strings.Fields(out.Text), " ") != "a1 a2 a3 a4 a5" || strings.Contains(out.Text, "More") || strings.Contains(out.Text, "quit") {
			t.Fatalf("corte %d: out=%q err=%v", off, out.Text, err)
		}
		if got := written(); got != "show ap summary\n  " {
			t.Fatalf("corte %d: escrito %q", off, got)
		}
	}
}

// Una pregunta de confirmación (y/N) no se contesta: no se escribe nada, queda incompleto, error y sesión inservible.
func TestAireOSPreguntaDeConfirmacion(t *testing.T) {
	for _, q := range []string{
		"\r\nAre you sure you want to proceed? (y/N)", "\r\nAre you sure you want to continue? (y/n) ", "\r\nSave? (Y/n)",
		"\r\nAre you sure you want to proceed? ",
	} {
		f, d, err := openAire(t, aireP, func(l string) (string, string) {
			if l == "show run-config" {
				return "parte\r\n" + q, "-"
			}
			return "", ""
		}, "", "")
		if err != nil {
			t.Fatal(err)
		}
		out, err := d.Run(context.Background(), "show run-config", 2*time.Second)
		if !errors.Is(err, platform.ErrConfirmPrompt) || !out.Incomplete {
			t.Fatalf("%q: out=%+v err=%v", q, out, err)
		}
		time.Sleep(30 * time.Millisecond)
		if got := f.written(); got != "show run-config\n" {
			t.Fatalf("%q: escrito %q", q, got)
		}
		if _, err := d.Run(context.Background(), "show sysinfo", time.Second); err == nil || d.Err() == nil {
			t.Fatalf("%q: la sesión sigue usable", q)
		}
	}
}

// Un show cuya salida mencione «(y/N)» a mitad de línea no es una pregunta.
func TestAireOSSalidaConYNNoEsPregunta(t *testing.T) {
	_, d, err := openAire(t, aireP, func(l string) (string, string) {
		if l == "show x" {
			return "Enable (y/N) setting is on\r\nfin\r\n", ""
		}
		return "", ""
	}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := d.Run(context.Background(), "show x", 2*time.Second); err != nil || out.Incomplete {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

// Las demás plataformas no cambian: bytes escritos por Open con IOS «SW1>» y con ASA «asa>».
func TestBytesEscritosIOSyASA(t *testing.T) {
	for name, tc := range map[string]struct{ first, host, want string }{
		"ios": {"SW1>", "SW1", "enable\nen\nterminal length 0\nterminal width 0\n"},
		"asa": {"asa> ", "asa", "enable\nen\nterminal length 0\nterminal pager 0\nterminal width 0\nterminal width 511\n"},
	} {
		f, r, w := startFake(t, tc.first, tc.first, func(line string) (string, string) {
			switch {
			case line == "enable":
				return "", "Password: "
			case line == "en":
				return "", tc.host + "# "
			case name == "asa" && (line == "terminal length 0" || line == "terminal width 0"):
				return "ERROR: % Invalid input detected at '^' marker.\r\n", ""
			}
			return "", ""
		})
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New([]byte("en"))); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := f.written(); got != tc.want {
			t.Errorf("%s: escrito %q, se esperaba %q", name, got, tc.want)
		}
	}
}
