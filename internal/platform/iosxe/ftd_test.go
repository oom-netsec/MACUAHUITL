package iosxe

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

func ftdReply(ver string) func(string) (string, string) {
	return func(line string) (string, string) {
		switch line {
		case "show version":
			return strings.ReplaceAll(ver, "\n", "\r\n"), ""
		case "show pager":
			return "no pager\r\n", ""
		case "terminal length 0", "terminal width 0":
			return "Command not valid: terminal\r\n", ""
		}
		return "", ""
	}
}

// Fixtures de show version de FTDv, Secure Firewall y 1120, armadas con la forma de la documentación, sin validar en laboratorio.
func TestDetectFTD(t *testing.T) {
	for _, f := range []string{"ftd-ftdv", "ftd-secure-firewall", "ftd-1120", "ftd-asa5508x", "ftd-isa3000"} {
		_, r, w := startFake(t, "> ", "> ", ftdReply(asaVersion(t, dir(f))))
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if p, err := d.Detect(context.Background()); err != nil || p != "ftd" {
			t.Fatalf("%s: Detect = %q, %v", f, p, err)
		}
	}
}

// La salida de FTD puede citar la versión de lina: gana ftd. Y un ASA que menciona FTD en texto libre sigue siendo asa.
func TestDetectFTDAntesQueASA(t *testing.T) {
	both := asaVersion(t, dir("ftd-ftdv")) + "\nCisco Adaptive Security Appliance Software Version 9.18(2)\n"
	_, r, w := startFake(t, "> ", "> ", ftdReply(both))
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if p, _ := d.Detect(context.Background()); p != "ftd" {
		t.Fatalf("Detect = %q", p)
	}
	asaTxt := asaVersion(t, dir("asa-asav")) + "\nModel : migrated to Cisco Firepower Threat Defense soon\n"
	_, r, w = startFake(t, "asa# ", "asa# ", ftdReply(asaTxt))
	d = New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if p, _ := d.Detect(context.Background()); p != "asa" {
		t.Fatalf("Detect = %q", p)
	}
}

// Sin nombre de host y sin enable: Open no manda «enable»; los «terminal …» rechazados no rompen la sesión.
func TestFTDOpenSinEnable(t *testing.T) {
	f, r, w := startFake(t, "Copyright 2004-2023, Cisco\r\n\r\n> ", "> ", ftdReply(""))
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New([]byte("en"))); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(f.written(), "enable") {
		t.Fatalf("se escribió %q", f.written())
	}
	if d.Hostname() != "" {
		t.Fatalf("Hostname = %q", d.Hostname())
	}
	out, err := d.Run(context.Background(), "show pager", 5*time.Second)
	if err != nil || out.Text != "no pager\n" {
		t.Fatalf("out = %q, %v", out.Text, err)
	}
}

// Primer login: cambio de contraseña obligatorio o EULA. Open aborta sin escribir NADA (ni el secreto ni un Enter).
func TestFTDPrimerLoginNoEscribeNada(t *testing.T) {
	for _, first := range []string{
		"You must change your password\r\nEnter new password: ",
		"You must change your password\r\n(current) UNIX password: ",
		"Enter new password: ",
		"Confirm new password: ",
		"Press <ENTER> to display the EULA: \r\nPlease enter 'YES' or press <ENTER> to AGREE to the EULA: ",
		"Please enter 'YES' or press <ENTER> to AGREE to the EULA: ",
		"You must accept the EULA to continue.\r\nPress <ENTER> to display the EULA: ",
		"Press <ENTER> to display the EULA: ",
	} {
		f, r, w := startFake(t, first, "> ", ftdReply(""))
		d := New().(*driver)
		err := d.Open(context.Background(), r, w, secret.New([]byte("en")))
		if !errors.Is(err, platform.ErrFirstLogin) {
			t.Fatalf("%q: Open = %v", first, err)
		}
		time.Sleep(20 * time.Millisecond)
		if got := f.written(); got != "" {
			t.Fatalf("%q: se escribió %q", first, got)
		}
	}
}

// Líneas de salida que empiezan con «>» (BGP, tablas) y una «>» suelta a mitad de la salida no cortan el comando:
// el fin es el segundo prompt seguido, aunque el equipo entregue la salida en pedazos.
func TestFTDPromptNoCortaSalida(t *testing.T) {
	r, w := scriptedDev(t, func(out func(string)) { out("> ") }, func(line string, out func(string)) {
		if line != "show bgp" {
			out(line + "\r\n> ")
			return
		}
		out("show bgp\r\n")
		for _, p := range []string{"   Network          Next Hop\r\n", ">", "  ", "10.0.0.0/8      192.0.2.1\r\n", ">\r\n", "  172.16.0.0/12  192.0.2.2\r\n"} {
			out(p)
			time.Sleep(30 * time.Millisecond)
		}
		out("fin\r\n> ")
	})
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show bgp", 5*time.Second)
	if err != nil || out.Incomplete {
		t.Fatal(err, out.Incomplete)
	}
	want := "   Network          Next Hop\n>  10.0.0.0/8      192.0.2.1\n>\n  172.16.0.0/12  192.0.2.2\nfin\n"
	if out.Text != want {
		t.Fatalf("texto %q", out.Text)
	}
}

// scriptedDev es un equipo que responde con pedazos y pausas: handle recibe cada línea y escribe lo que quiera. Las
// líneas que llegan mientras handle trabaja quedan en cola (como el Enter de cola de un FTD ocupado). El equipo anota
// las líneas recibidas.
type devLog struct {
	mu    sync.Mutex
	lines []string
}

func (l *devLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

func scriptedDev(t *testing.T, first func(out func(string)), handle func(line string, out func(string))) (io.Reader, io.Writer) {
	r, w, _ := scriptedDevLog(t, first, handle)
	return r, w
}

func scriptedDevLog(t *testing.T, first func(out func(string)), handle func(line string, out func(string))) (io.Reader, io.Writer, *devLog) {
	t.Helper()
	devR, drvW := io.Pipe()
	drvR, devW := io.Pipe()
	lg := &devLog{}
	q := make(chan string, 64)
	t.Cleanup(func() { drvW.Close(); devW.Close() })
	out := func(s string) { io.WriteString(devW, s) }
	go func() {
		var buf []byte
		b := make([]byte, 1)
		for {
			if _, err := devR.Read(b); err != nil {
				close(q)
				return
			}
			if b[0] != '\n' {
				buf = append(buf, b[0])
				continue
			}
			lg.mu.Lock()
			lg.lines = append(lg.lines, string(buf))
			lg.mu.Unlock()
			q <- string(buf)
			buf = buf[:0]
		}
	}()
	go func() {
		first(out)
		for line := range q {
			handle(line, out)
		}
	}()
	return drvR, drvW, lg
}

// Una pausa a mitad de la salida, tras una línea «> », no corta el comando ni desfasa el siguiente mientras no se
// llegue al límite de la red de seguridad (3 × 400 ms): el fin es el segundo prompt seguido.
func TestFTDPausaLargaNoDesfasa(t *testing.T) {
	for _, pausa := range []time.Duration{300 * time.Millisecond, 500 * time.Millisecond} {
		r, w := scriptedDev(t, func(out func(string)) { out("> ") }, func(line string, out func(string)) {
			out(line + "\r\n")
			if line == "show a" {
				out("linea1\r\n> ")
				time.Sleep(pausa)
				out("resto\r\n")
			} else if line == "show b" {
				out("b1\r\n")
			}
			out("> ")
		})
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatal(err)
		}
		a, err := d.Run(context.Background(), "show a", 5*time.Second)
		if err != nil || a.Text != "linea1\n> resto\n" || a.Incomplete {
			t.Fatalf("%s: a = %q, %v, %v", pausa, a.Text, err, a.Incomplete)
		}
		b, err := d.Run(context.Background(), "show b", 5*time.Second)
		if err != nil || b.Text != "b1\n" || b.Incomplete {
			t.Fatalf("%s: b = %q, %v, %v", pausa, b.Text, err, b.Incomplete)
		}
	}
}

// El fin confirmado son dos prompts seguidos: la salida queda sin el prompt extra (el eco del Enter de cola) y completa.
// El Enter de cola llega al equipo justo después del comando.
func TestFTDCentinelaConfirmaFin(t *testing.T) {
	r, w, lg := scriptedDevLog(t, func(out func(string)) { out("> ") }, func(line string, out func(string)) {
		out(line + "\r\n")
		if line == "show a" {
			out("uno\r\ndos\r\n")
		}
		out("> ")
	})
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	out, err := d.Run(context.Background(), "show a", 5*time.Second)
	if err != nil || out.Text != "uno\ndos\n" || out.Incomplete || time.Since(t0) > time.Second {
		t.Fatalf("out = %q, %v, %v, %s", out.Text, err, out.Incomplete, time.Since(t0))
	}
	got := lg.get()
	if i := slices.Index(got, "show a"); i < 0 || i+1 >= len(got) || got[i+1] != "" {
		t.Fatalf("el Enter de cola no llegó tras el comando: %q", got)
	}
}

// Si el equipo leyó el Enter antes o lo descartó, queda un solo prompt: tras ~1,2 s sin datos se acepta, pero la
// salida queda marcada como incompleta.
func TestFTDUnSoloPromptSeAceptaIncompleto(t *testing.T) {
	r, w := scriptedDev(t, func(out func(string)) { out("> ") }, func(line string, out func(string)) {
		if line == "" {
			return // Enter descartado
		}
		out(line + "\r\n")
		if line == "show a" {
			out("uno\r\n")
		}
		out("> ")
	})
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	out, err := d.Run(context.Background(), "show a", 10*time.Second)
	el := time.Since(t0)
	if err != nil || out.Text != "uno\n" || !out.Incomplete || el < time.Second || el > 2500*time.Millisecond {
		t.Fatalf("out = %q, %v, %v, %s", out.Text, err, out.Incomplete, el)
	}
}

// Una línea «> » suelta con una pausa de 1,3 s es indistinguible de un solo prompt final: se corta, pero marcada como
// incompleta (nunca en silencio).
func TestFTDPausaMayorQueLaRedDeSeguridadQuedaIncompleta(t *testing.T) {
	r, w := scriptedDev(t, func(out func(string)) { out("> ") }, func(line string, out func(string)) {
		out(line + "\r\n")
		if line == "show a" {
			out("linea1\r\n> ")
			time.Sleep(1300 * time.Millisecond)
			out("resto\r\n")
		}
		out("> ")
	})
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show a", 10*time.Second)
	if err != nil || !out.Incomplete {
		t.Fatalf("out = %q, %v, %v", out.Text, err, out.Incomplete)
	}
}

// IOS, ASA y NX-OS escriben exactamente lo de siempre: ni Enter de cola ni nada más.
func TestSinCentinelaEnOtrasPlataformas(t *testing.T) {
	for _, p := range []string{"SW1# ", "asa# ", "n9k# "} {
		f, r, w := startFake(t, p, p, func(string) (string, string) { return "", "" })
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Run(context.Background(), "show clock", 5*time.Second); err != nil {
			t.Fatal(err)
		}
		if got := f.written(); got != "terminal length 0\nterminal width 0\nshow clock\n" {
			t.Fatalf("%q: se escribió %q", p, got)
		}
	}
}

// Un banner de IOS que termina en una línea «>» y el prompt «SW1#» 200 ms después no es un FTD.
func TestIOSBannerTerminaEnMayorQueNoEsFTD(t *testing.T) {
	r, w := scriptedDev(t, func(out func(string)) {
		out("Authorized use only\r\n>")
		time.Sleep(200 * time.Millisecond)
		out("\r\nSW1# ")
	}, func(line string, out func(string)) { out(line + "\r\nSW1# ") })
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if d.Hostname() != "SW1" {
		t.Fatalf("Hostname = %q", d.Hostname())
	}
}

// Un «> » que llega antes del eco del comando no es el prompt de ese comando.
func TestFTDPromptSinEcoNoCuenta(t *testing.T) {
	r, w := scriptedDev(t, func(out func(string)) { out("> ") }, func(line string, out func(string)) {
		if line == "show c" {
			out("> ")
			time.Sleep(600 * time.Millisecond)
			out("show c\r\nc1\r\n> ")
			return
		}
		out(line + "\r\n> ")
	})
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	out, err := d.Run(context.Background(), "show c", 5*time.Second)
	if err != nil || out.Text != "> show c\nc1\n" {
		t.Fatalf("out = %q, %v", out.Text, err)
	}
}

// Un comando pegado de ~215 caracteres: el eco no siempre es literal (CRLF al envolver, «$» de scroll, retrocesos,
// truncado, « \r»). Nunca debe colgarse hasta el timeout de inactividad por culpa del eco.
func TestFTDEcoNoLiteralNoCuelga(t *testing.T) {
	cmd := "show " + strings.Repeat("abcdefghij", 20) + "tail-UNIQUE-98765"
	for name, echo := range map[string]func(string) string{
		"crlf":       func(l string) string { return l[:198] + "\r\n" + l[198:] },
		"scroll":     func(l string) string { return l[:100] + "$" + l[100:] },
		"retroceso":  func(l string) string { return l[:50] + "X\x08" + l[50:] },
		"truncado":   func(l string) string { return l[:190] },
		"espacio-cr": func(l string) string { return l[:198] + " \r" + l[198:] },
	} {
		r, w := scriptedDev(t, func(out func(string)) { out("> ") }, func(line string, out func(string)) {
			if line == cmd {
				out(echo(line) + "\r\nout\r\n> ")
				return
			}
			out(line + "\r\n> ")
		})
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		limit := 1000 * time.Millisecond // con eco reconocible basta una pausa; sin él, la red de seguridad (3 pausas)
		if name == "truncado" {
			limit = 4 * time.Second
		}
		out, err := d.Run(context.Background(), cmd, 30*time.Second)
		if err != nil || !strings.HasSuffix(out.Text, "out\n") || time.Since(t0) > limit {
			t.Fatalf("%s: out = %q, %v, %v", name, out.Text, err, time.Since(t0))
		}
	}
}
