package simulator

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func transcripts(t *testing.T, platform string) string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "transcripts", platform)
}

func readUntil(t *testing.T, r *bufio.Reader, suffix string) string {
	t.Helper()
	var b strings.Builder
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := r.ReadByte()
		if err != nil {
			t.Fatalf("read: %v (got %q)", err, b.String())
		}
		b.WriteByte(c)
		if strings.HasSuffix(b.String(), suffix) {
			return b.String()
		}
	}
	t.Fatalf("timeout waiting for %q, got %q", suffix, b.String())
	return ""
}

func TestSimulatorBasics(t *testing.T) {
	dir := transcripts(t, "ios-xe")
	addr, hostKey := Start(t, Config{Hostname: "SW1", Username: "admin", Password: "pw", Enable: "en", Transcripts: dir})
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            "admin",
		Auth:            []ssh.AuthMethod{ssh.Password("pw")},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequestPty("vt100", 24, 200, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	in, _ := s.StdinPipe()
	outPipe, _ := s.StdoutPipe()
	out := bufio.NewReader(outPipe)
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	readUntil(t, out, "SW1>")
	io.WriteString(in, "enable\n")
	readUntil(t, out, "Password: ")
	io.WriteString(in, "en\n")
	readUntil(t, out, "SW1#")
	io.WriteString(in, "terminal length 0\n")
	readUntil(t, out, "SW1#")
	io.WriteString(in, "show version\n")
	got := readUntil(t, out, "SW1#")
	want, _ := os.ReadFile(filepath.Join(dir, "show_version.txt"))
	body := strings.SplitN(string(want), "\n", 2)[1]
	if !strings.Contains(strings.ReplaceAll(got, "\r\n", "\n"), body) {
		t.Fatalf("show version output mismatch:\n%s", got)
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	addr, hostKey := Start(t, Config{Hostname: "SW1", Username: "admin", Password: "pw", Transcripts: transcripts(t, "ios-xe")})
	_, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "admin", Auth: []ssh.AuthMethod{ssh.Password("x")}, HostKeyCallback: ssh.FixedHostKey(hostKey)})
	if err == nil {
		t.Fatal("wrong password accepted")
	}
}

// El simulador cambia el modo de un puerto: dynamic desirable y access salen en el running, dynamic auto (de fábrica) no, y
// `no switchport mode` devuelve el puerto a dynamic auto. Un dynamic sin vecino opera como down. Modelo sin validar en laboratorio.
func TestSimulatorSwitchportModeChanges(t *testing.T) {
	const gi = "GigabitEthernet1/0/1"
	addr, hostKey := Start(t, Config{Hostname: "SW1", Username: "admin", Password: "pw", StartPrivileged: true, Interfaces: map[string][]string{gi: {"switchport mode access"}}})
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "admin", Auth: []ssh.AuthMethod{ssh.Password("pw")}, HostKeyCallback: ssh.FixedHostKey(hostKey)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RequestPty("vt100", 24, 200, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	in, _ := s.StdinPipe()
	outPipe, _ := s.StdoutPipe()
	out := bufio.NewReader(outPipe)
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	readUntil(t, out, "SW1#")
	run := func(cmd, prompt string) string {
		io.WriteString(in, cmd+"\n")
		return readUntil(t, out, prompt)
	}
	run("terminal length 0", "SW1#")
	run("configure terminal", "SW1(config)#")
	run("interface "+gi, "SW1(config-if)#")
	state := func() (running, switchport string) {
		run("end", "SW1#")
		running = run("show running-config interface "+gi, "SW1#")
		switchport = run("show interfaces "+gi+" switchport", "SW1#")
		run("configure terminal", "SW1(config)#")
		run("interface "+gi, "SW1(config-if)#")
		return
	}
	for _, c := range []struct{ line, admin, oper, inRunning string }{
		{"no switchport mode", "dynamic auto", "down", ""},
		{"switchport mode dynamic desirable", "dynamic desirable", "down", "switchport mode dynamic desirable"},
		{"switchport mode dynamic auto", "dynamic auto", "down", ""},
		{"switchport mode access", "static access", "static access", "switchport mode access"},
	} {
		run(c.line, "SW1(config-if)#")
		running, sw := state()
		if c.inRunning == "" && strings.Contains(running, "switchport mode") || c.inRunning != "" && !strings.Contains(running, c.inRunning) {
			t.Errorf("%s: running = %q", c.line, running)
		}
		if !strings.Contains(sw, "Administrative Mode: "+c.admin+"\r\n") || !strings.Contains(sw, "Operational Mode: "+c.oper+"\r\n") {
			t.Errorf("%s: switchport = %q", c.line, sw)
		}
	}
	// El filtro «| include Mode:» deja solo las líneas de modo.
	run("end", "SW1#")
	got := run("show interfaces "+gi+" switchport | include Mode:", "SW1#")
	if !strings.Contains(got, "Administrative Mode: static access\r\nOperational Mode: static access\r\n") || strings.Contains(got, "Name:") {
		t.Errorf("include Mode: = %q", got)
	}
}

func TestExecYSoloPublickey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	var log []string
	rec := &Recorder{}
	addr, hk := Start(t, Config{Hostname: "pi", Username: "pi", Transcripts: transcripts(t, "ios-xe"), NoPassword: true,
		AuthorizedKeys: []ssh.PublicKey{signer.PublicKey()}, AuthLog: &log, Recorder: rec,
		Exec: func(cmd string) string { return "ok:" + cmd + "\n" }})
	cc := func(auth ssh.AuthMethod) (*ssh.Client, error) {
		return ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "pi", Auth: []ssh.AuthMethod{auth}, HostKeyCallback: ssh.FixedHostKey(hk), Timeout: 3 * time.Second})
	}
	if _, err := cc(ssh.Password("x")); err == nil {
		t.Fatal("password aceptada con NoPassword")
	}
	c, err := cc(ssh.PublicKeys(signer))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, pty := range []bool{false, true} {
		s, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		if pty {
			if err := s.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
				t.Fatal(err)
			}
		}
		out, err := s.Output("echo hola")
		if err != nil || string(out) != "ok:echo hola\n" {
			t.Fatalf("exec pty=%v: %q %v", pty, out, err)
		}
	}
	if l := rec.Lines(); len(l) != 2 || l[0] != "!exec pty=false echo hola" || l[1] != "!exec pty=true echo hola" {
		t.Fatalf("recorder: %v", l)
	}
	if len(log) == 0 {
		t.Fatal("AuthLog vacío")
	}
}

// shellAbierto abre un shell con contraseña y espera el prompt.
func shellAbierto(t *testing.T, addr string, hostKey ssh.PublicKey) *bufio.Reader {
	t.Helper()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "admin", Auth: []ssh.AuthMethod{ssh.Password("pw")}, HostKeyCallback: ssh.FixedHostKey(hostKey)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	s, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	// Sin StdinPipe el cliente manda EOF por stdin al abrir y el shell termina solo: la sesión
	// ya no estaría abierta cuando la prueba corte.
	if _, err := s.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	outPipe, _ := s.StdoutPipe()
	out := bufio.NewReader(outPipe)
	if err := s.Shell(); err != nil {
		t.Fatal(err)
	}
	readUntil(t, out, "SW1>")
	return out
}

func TestHangupCortaSoloLasSesionesAbiertas(t *testing.T) {
	h := &Hangup{}
	addr, hostKey := Start(t, Config{Hostname: "SW1", Username: "admin", Password: "pw", Hangup: h})
	out := shellAbierto(t, addr, hostKey)
	if n := h.Now(); n != 1 {
		t.Fatalf("cortó %d sesiones, se esperaba 1", n)
	}
	if _, err := out.ReadByte(); err != io.EOF {
		t.Fatalf("la sesión cortada sigue viva: %v", err)
	}
	// La que se abre después no la toca el corte anterior: sigue abierta hasta el siguiente.
	shellAbierto(t, addr, hostKey)
	if n := h.Now(); n != 1 {
		t.Fatalf("segundo corte: %d sesiones", n)
	}
	if n := h.Now(); n != 0 {
		t.Fatalf("sin sesiones abiertas cortó %d", n)
	}
}

// TestOTPDosPreguntas: con Config.OTP el keyboard-interactive hace una sola ronda MFA con dos preguntas;
// una respuesta mala es un fallo por ronda (como sshd).
func TestOTPDosPreguntas(t *testing.T) {
	var attempts atomic.Int32
	addr, _ := Start(t, Config{Hostname: "SW", Username: "admin", Password: "pw", OTP: "123456", Attempts: &attempts, Transcripts: transcripts(t, "ios-xe")})
	dial := func(pass, code string) ([]string, error) {
		var seen []string
		kb := ssh.KeyboardInteractive(func(name, instr string, qs []string, echo []bool) ([]string, error) {
			seen = append(seen, name, instr, strings.Join(qs, "|"), fmt.Sprint(echo))
			return []string{pass, code}, nil
		})
		c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "admin", Auth: []ssh.AuthMethod{kb}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second})
		if err == nil {
			c.Close()
		}
		return seen, err
	}
	seen, err := dial("pw", "000000")
	if err == nil || attempts.Load() != 1 {
		t.Fatalf("código malo: err=%v attempts=%d, quería fallo y 1", err, attempts.Load())
	}
	if want := []string{"MFA", "Enter password and code", "Password: |Verification code: ", "[false true]"}; !slices.Equal(seen, want) {
		t.Fatalf("callback = %q, quería %q", seen, want)
	}
	if _, err := dial("pw", "123456"); err != nil {
		t.Fatalf("par bueno: %v", err)
	}
}

// Con MFA no hay atajo por el método password: un cliente que solo ofrece password no entra.
func TestOTPSinPasswordDirecto(t *testing.T) {
	addr, _ := Start(t, Config{Hostname: "R1", Username: "admin", Password: "pw", OTP: "123456"})
	cfg := &ssh.ClientConfig{User: "admin", Auth: []ssh.AuthMethod{ssh.Password("pw")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}
	if c, err := ssh.Dial("tcp", addr, cfg); err == nil {
		c.Close()
		t.Fatal("entró con password sin el código")
	}
}

// telnetCliente es lo mínimo del lado de la prueba: lee quitando las negociaciones IAC y escribe con CR NUL.
type telnetCliente struct {
	c   net.Conn
	r   *bufio.Reader
	neg []string // negociaciones recibidas: "WILL 1", "DO 31"...
}

func dialTelnet(t *testing.T, addr string) *telnetCliente {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &telnetCliente{c: c, r: bufio.NewReader(c)}
}

func (k *telnetCliente) hasta(t *testing.T, suffix string) string {
	t.Helper()
	k.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var b strings.Builder
	for !strings.HasSuffix(b.String(), suffix) {
		c, err := k.r.ReadByte()
		if err != nil {
			t.Fatalf("leyendo hasta %q: %v (llegó %q)", suffix, err, b.String())
		}
		if c != 255 {
			b.WriteByte(c)
			continue
		}
		cmd, _ := k.r.ReadByte()
		opt, _ := k.r.ReadByte()
		k.neg = append(k.neg, map[byte]string{251: "WILL", 252: "WONT", 253: "DO", 254: "DONT"}[cmd]+" "+strconv.Itoa(int(opt)))
	}
	return b.String()
}

func (k *telnetCliente) linea(s string) { k.c.Write(append([]byte(s), '\r', 0)) }

func TestTelnetLoginYComando(t *testing.T) {
	var att atomic.Int32
	rec := &Recorder{}
	addr := StartTelnet(t, Config{Hostname: "SW1", Username: "admin", Password: "pw", Attempts: &att, Recorder: rec, Transcripts: transcripts(t, "ios-xe")})
	k := dialTelnet(t, addr)
	k.hasta(t, "Username: ")
	k.linea("admin")
	k.hasta(t, "Password: ")
	k.linea("mala")
	k.hasta(t, "% Login invalid\r\n\r\nUsername: ")
	k.linea("admin")
	if out := k.hasta(t, "Password: "); strings.Contains(out, "mala") {
		t.Fatalf("hizo eco de la contraseña: %q", out)
	}
	k.linea("pw")
	k.hasta(t, "SW1>")
	k.linea("terminal length 0")
	k.hasta(t, "SW1>")
	k.linea("show version")
	if out := k.hasta(t, "SW1>"); !strings.Contains(out, "Cisco") {
		t.Fatalf("show version = %q", out)
	}
	if att.Load() != 2 {
		t.Errorf("Attempts = %d, quería 2", att.Load())
	}
	if !slices.Contains(k.neg, "WILL 1") || !slices.Contains(k.neg, "WILL 3") || !slices.Contains(k.neg, "DO 31") {
		t.Errorf("negociación = %v", k.neg)
	}
	// NAWS (RFC 1073): el tamaño que manda el cliente queda en el Recorder.
	k.c.Write([]byte{255, 250, 31, 0, 200, 0, 24, 255, 240})
	k.linea("")
	k.hasta(t, "SW1>")
	if !slices.Contains(rec.lines, "!naws 200x24") {
		t.Errorf("Recorder = %v", rec.lines)
	}
}

// Password de línea (sin usuario), banner con «Password:» a media línea y un equipo que no ofrece WILL ECHO.
func TestTelnetPasswordDeLineaBannerYSinEco(t *testing.T) {
	addr := StartTelnet(t, Config{Hostname: "SW1", Password: "pw", TelnetLinePassword: true, TelnetNoEcho: true,
		TelnetBanner: "Authorized access only. Password: changes are logged\n"})
	k := dialTelnet(t, addr)
	if out := k.hasta(t, "logged\r\nPassword: "); !strings.Contains(out, "Authorized access only. Password: changes are logged") {
		t.Fatalf("banner = %q", out)
	}
	k.linea("mala")
	k.hasta(t, "% Bad passwords\r\n\r\nPassword: ")
	k.linea("pw")
	k.hasta(t, "SW1>")
	if slices.Contains(k.neg, "WILL 1") {
		t.Errorf("ofreció WILL ECHO con TelnetNoEcho: %v", k.neg)
	}
}
