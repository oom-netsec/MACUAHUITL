package simulator

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
