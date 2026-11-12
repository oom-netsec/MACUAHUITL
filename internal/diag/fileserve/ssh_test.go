package fileserve

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func sshDial(addr, user, pass string, legacyOnly bool) (*ssh.Client, error) {
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(pass)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	if legacyOnly { // lo único que ofrece un IOS 15.x viejo
		cfg.KeyExchanges = []string{"diffie-hellman-group14-sha1"}
		cfg.Ciphers = []string{"aes128-cbc"}
		cfg.HostKeyAlgorithms = []string{ssh.KeyAlgoRSA}
		cfg.MACs = []string{"hmac-sha1"}
	}
	return ssh.Dial("tcp", addr, cfg)
}

func mustDial(t *testing.T, addr string, r Ready) *ssh.Client {
	t.Helper()
	c, err := sshDial(addr, r.User, r.Pass, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestSFTPServer(t *testing.T) {
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "a.bin"), []byte("contenido A"), 0o600)
	os.Mkdir(filepath.Join(pub, "sub"), 0o700)
	os.WriteFile(filepath.Join(pub, "sub", "x"), []byte("x"), 0o600)
	os.Symlink("/etc/hostname", filepath.Join(pub, "enlace"))
	recv := t.TempDir()
	s, r := startCfg(t, Config{Proto: "sftp", FromDir: pub, Write: true, RecvDir: recv})
	if r.User == "" || len(r.Pass) < 12 || len(r.Fingerprints) != 2 || !strings.HasPrefix(r.Fingerprints[0], "SHA256:") {
		t.Fatalf("ready = %+v", r)
	}
	cl, err := sftp.NewClient(mustDial(t, s.addr, r))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	// Listado: solo los archivos regulares de primer nivel.
	ents, err := cl.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "a.bin" {
		t.Fatalf("listado = %v", ents)
	}
	f, err := cl.Open("/a.bin")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(f); string(b) != "contenido A" {
		t.Fatalf("lectura = %q", b)
	}
	f.Close()
	for _, p := range []string{"/sub/x", "/enlace", "/etc/passwd", "/../etc/passwd", "/sub", "/no-existe"} {
		if g, err := cl.Open(p); err == nil {
			g.Close()
			t.Errorf("Open(%s) debió fallar", p)
		}
	}
	// Escritura: archivo nuevo en la carpeta de recepción.
	w, err := cl.Create("/running-config")
	if err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("ip route 0.0.0.0\n"), 1000)
	w.Write(data)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(recv, "running-config"))
	st, _ := os.Stat(filepath.Join(recv, "running-config"))
	if !bytes.Equal(got, data) || st.Mode().Perm() != 0o600 {
		t.Fatalf("recibido mal (%v)", st.Mode())
	}
	// Nombre con ruta y "..": cae como nombre base dentro de la carpeta.
	w, err = cl.Create("/../../tmp/evil")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("1"))
	w.Close()
	if _, err := os.Stat(filepath.Join(recv, "evil")); err != nil {
		t.Fatalf("no cayó en la carpeta: %v", err)
	}
	// Nunca sobrescribe.
	if w, err := cl.Create("/running-config"); err == nil {
		w.Write([]byte("pisado"))
		w.Close()
		t.Fatal("sobrescribió o aceptó un existente")
	}
	if b, _ := os.ReadFile(filepath.Join(recv, "running-config")); !bytes.Equal(b, data) {
		t.Fatal("el existente cambió")
	}
	// Ni borrar, renombrar, carpetas ni enlaces.
	if cl.Remove("/a.bin") == nil || cl.Rename("/a.bin", "/b.bin") == nil || cl.Mkdir("/nueva") == nil ||
		cl.Symlink("/etc/passwd", "/ln") == nil || cl.RemoveDirectory("/sub") == nil {
		t.Fatal("una operación de modificación fue aceptada")
	}
	if _, err := os.Stat(filepath.Join(pub, "a.bin")); err != nil {
		t.Fatal("se borró un archivo publicado")
	}
	for _, n := range []string{"b.bin", "nueva", "ln"} {
		for _, d := range []string{pub, recv} {
			if _, err := os.Lstat(filepath.Join(d, n)); err == nil {
				t.Errorf("apareció %s en %s", n, d)
			}
		}
	}
	// Auditoría: lectura y escrituras con su ruta y hash.
	var okW, okR int
	for _, x := range s.transfers() {
		sum := sha256.Sum256(data)
		if x.Proto == "sftp" && x.Result == "ok" && x.Dir == "escritura" && x.File == "running-config" && x.SHA256 == hex.EncodeToString(sum[:]) {
			okW++
		}
		if x.Proto == "sftp" && x.Result == "ok" && x.Dir == "lectura" && x.Path == filepath.Join(pub, "a.bin") {
			okR++
		}
	}
	if okW != 1 || okR != 1 {
		t.Fatalf("transferencias = %+v", s.transfers())
	}
}

func TestSFTPCapsAndSeparateModes(t *testing.T) {
	recv := t.TempDir()
	s, r := startCfg(t, Config{Proto: "sftp", Write: true, RecvDir: recv, MaxFile: 100, MaxTotal: 150})
	cl, _ := sftp.NewClient(mustDial(t, s.addr, r))
	defer cl.Close()
	w, _ := cl.Create("/grande")
	_, err1 := w.Write(make([]byte, 200))
	err2 := w.Close()
	if err1 == nil && err2 == nil {
		t.Fatal("excedió el tope por archivo sin error")
	}
	if _, err := os.Stat(filepath.Join(recv, "grande")); err == nil {
		t.Fatal("quedó un archivo que excedió el tope")
	}
	w, _ = cl.Create("/uno")
	w.Write(make([]byte, 100))
	w.Close()
	w, _ = cl.Create("/dos")
	_, e1 := w.Write(make([]byte, 60))
	e2 := w.Close()
	if e1 == nil && e2 == nil {
		t.Fatal("excedió el tope total sin error")
	}
	if _, err := os.Stat(filepath.Join(recv, "dos")); err == nil {
		t.Fatal("quedó un archivo que excedió el tope total")
	}
	// Sin archivos que leer: lectura apagada.
	if f, err := cl.Open("/uno"); err == nil {
		f.Close()
		t.Fatal("lectura habilitada sin habérsela pedido")
	}
}

func TestSFTPWriteDisabled(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	s, r := startCfg(t, Config{Proto: "sftp", Files: []string{p}})
	cl, _ := sftp.NewClient(mustDial(t, s.addr, r))
	defer cl.Close()
	if w, err := cl.Create("/x"); err == nil {
		w.Close()
		t.Fatal("escritura habilitada sin habérsela pedido")
	}
	if f, err := cl.Open("/a.bin"); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
}

// Sin shell, sin exec ajeno, sin reenvío de puertos ni de agente.
// newSession abre una sesión; el servidor limita las simultáneas por conexión y devuelve el cupo
// un instante después de que el cliente cierra la anterior, así que se reintenta un momento.
func newSession(t *testing.T, c *ssh.Client) *ssh.Session {
	t.Helper()
	var err error
	for range 100 {
		var s *ssh.Session
		if s, err = c.NewSession(); err == nil {
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(err)
	return nil
}

func TestSSHRejectsShellExecAndForwarding(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	for _, proto := range []string{"scp", "sftp"} {
		s, r := startCfg(t, Config{Proto: proto, Files: []string{p}, Write: true, RecvDir: t.TempDir()})
		c := mustDial(t, s.addr, r)
		sess := newSession(t, c)
		if err := sess.Shell(); err == nil {
			t.Errorf("%s: shell aceptado", proto)
		}
		sess.Close()
		sess = newSession(t, c)
		if err := sess.RequestPty("xterm", 24, 80, nil); err == nil {
			t.Errorf("%s: pty aceptado", proto)
		}
		sess.Close()
		cmds := []string{"ls /", "sh -c id", "scp -r -t /tmp", "scp -t; id", "scp -f a.bin; id", "/bin/sh", "scp -S /bin/sh -t x"}
		for _, cmd := range cmds {
			sess = newSession(t, c)
			if err := sess.Run(cmd); err == nil {
				t.Errorf("%s: exec %q aceptado", proto, cmd)
			}
			sess.Close()
		}
		if _, err := c.Dial("tcp", "127.0.0.1:22"); err == nil {
			t.Errorf("%s: direct-tcpip aceptado", proto)
		}
		if _, err := c.Listen("tcp", "127.0.0.1:0"); err == nil {
			t.Errorf("%s: tcpip-forward aceptado", proto)
		}
		sess = newSession(t, c)
		if ok, _ := sess.SendRequest("auth-agent-req@openssh.com", true, nil); ok {
			t.Errorf("%s: agente aceptado", proto)
		}
		sess.Close()
		// El subsistema del otro protocolo tampoco.
		other := map[string]string{"scp": "sftp", "sftp": ""}[proto]
		if other != "" {
			sess = newSession(t, c)
			if err := sess.RequestSubsystem(other); err == nil {
				t.Errorf("%s: subsistema %s aceptado", proto, other)
			}
			sess.Close()
		}
		if proto == "sftp" {
			sess = newSession(t, c)
			if err := sess.RequestSubsystem("netconf"); err == nil {
				t.Error("subsistema netconf aceptado")
			}
			sess.Close()
			sess = newSession(t, c)
			if err := sess.Run("scp -f a.bin"); err == nil {
				t.Error("sftp: scp aceptado")
			}
			sess.Close()
		}
		var rej, execs int
		for _, x := range s.transfers() {
			if x.Rejected {
				rej++
			}
			if x.Rejected && strings.Contains(x.Error, "exec rechazado") {
				execs++
			}
		}
		if rej < 5 || execs < len(cmds) { // cada exec ajeno queda registrado como rechazado
			t.Errorf("%s: rechazos no registrados (%d, exec %d): %+v", proto, rej, execs, s.transfers())
		}
	}
}

func TestSSHAuth(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	s, r := startCfg(t, Config{Proto: "sftp", Files: []string{p}})
	if _, err := sshDial(s.addr, r.User, "mala", false); err == nil {
		t.Fatal("contraseña incorrecta aceptada")
	}
	if _, err := sshDial(s.addr, "otro", r.Pass, false); err == nil {
		t.Fatal("usuario incorrecto aceptado")
	}
	// Tras varios fallos desde la misma IP ni la contraseña buena entra.
	for i := 0; i < 6; i++ {
		sshDial(s.addr, r.User, "mala", false)
	}
	if c, err := sshDial(s.addr, r.User, r.Pass, false); err == nil {
		c.Close()
		t.Fatal("el bloqueo por fallos no cerró la puerta")
	}
	// Credenciales distintas en cada servidor.
	_, r2 := startCfg(t, Config{Proto: "sftp", Files: []string{p}})
	if r.Pass == r2.Pass {
		t.Fatal("la contraseña se repite entre sesiones")
	}
}

func TestSSHAllowListAndLegacy(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	s, r := startCfg(t, Config{Proto: "sftp", Files: []string{p}, Allow: []netip.Addr{netip.MustParseAddr("10.9.9.9")}})
	if c, err := sshDial(s.addr, r.User, r.Pass, false); err == nil {
		c.Close()
		t.Fatal("origen fuera de la lista aceptado")
	}
	// Algoritmos de IOS 15.x: solo con Legacy.
	s2, r2 := startCfg(t, Config{Proto: "scp", Files: []string{p}, Legacy: true})
	c, err := sshDial(s2.addr, r2.User, r2.Pass, true)
	if err != nil {
		t.Fatalf("cliente antiguo con Legacy: %v", err)
	}
	c.Close()
	s3, r3 := startCfg(t, Config{Proto: "scp", Files: []string{p}})
	if c, err := sshDial(s3.addr, r3.User, r3.Pass, true); err == nil {
		c.Close()
		t.Fatal("algoritmos antiguos aceptados sin Legacy")
	}
}

// ---- scp a mano: el protocolo de control es de unas pocas líneas ----

func scpUpload(c *ssh.Client, target, name string, data []byte) error {
	sess, err := c.NewSession()
	if err != nil {
		return err
	}
	defer sess.Close()
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.Start("scp -t " + target); err != nil {
		return err
	}
	b := make([]byte, 1)
	ack := func() error {
		if _, err := io.ReadFull(out, b); err != nil {
			return err
		}
		if b[0] != 0 {
			msg := make([]byte, 100)
			n, _ := out.Read(msg)
			return fmt.Errorf("scp: %q", msg[:n])
		}
		return nil
	}
	if err := ack(); err != nil {
		return err
	}
	fmt.Fprintf(in, "C0644 %d %s\n", len(data), name)
	if err := ack(); err != nil {
		return err
	}
	in.Write(data)
	in.Write([]byte{0})
	if err := ack(); err != nil {
		return err
	}
	in.Close()
	return sess.Wait()
}

func scpDownload(c *ssh.Client, path string) ([]byte, error) {
	sess, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.Start("scp -f " + path); err != nil {
		return nil, err
	}
	in.Write([]byte{0})
	var line []byte
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(out, one); err != nil {
			return nil, err
		}
		if one[0] == '\n' {
			break
		}
		line = append(line, one[0])
	}
	if len(line) == 0 || line[0] != 'C' {
		return nil, fmt.Errorf("scp: %q", line)
	}
	var mode, size int
	var name string
	fmt.Sscanf(string(line[1:]), "%o %d %s", &mode, &size, &name)
	in.Write([]byte{0})
	data := make([]byte, size)
	if _, err := io.ReadFull(out, data); err != nil {
		return nil, err
	}
	io.ReadFull(out, one) // 0 final
	in.Write([]byte{0})
	return data, nil
}

func TestSCPServer(t *testing.T) {
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "img.bin"), []byte("imagen"), 0o600)
	recv := t.TempDir()
	s, r := startCfg(t, Config{Proto: "scp", FromDir: pub, Write: true, RecvDir: recv, MaxFile: 1000, MaxTotal: 1500})
	c := mustDial(t, s.addr, r)
	got, err := scpDownload(c, "img.bin")
	if err != nil || string(got) != "imagen" {
		t.Fatalf("descarga: %q %v", got, err)
	}
	for _, p := range []string{"nada", "../img.bin", "sub/img.bin"} {
		if _, err := scpDownload(c, p); err == nil {
			t.Errorf("descarga de %q aceptada", p)
		}
	}
	cfg := bytes.Repeat([]byte("x"), 500)
	if err := scpUpload(c, "cfg.txt", "cfg.txt", cfg); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(recv, "cfg.txt")); !bytes.Equal(b, cfg) {
		t.Fatal("contenido recibido distinto")
	}
	// Carpeta de destino ("."): manda el nombre de la orden C, saneado.
	if err := scpUpload(c, ".", "../../r1.cfg", []byte("1")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(recv, "r1.cfg")); err != nil {
		t.Fatal("el nombre con .. no cayó en la carpeta")
	}
	// Existente, sobre el tope por archivo, sobre el total.
	if err := scpUpload(c, "cfg.txt", "cfg.txt", []byte("pisado")); err == nil {
		t.Error("sobrescribió")
	}
	if b, _ := os.ReadFile(filepath.Join(recv, "cfg.txt")); !bytes.Equal(b, cfg) {
		t.Error("el existente cambió")
	}
	c2 := mustDial(t, s.addr, r)
	if err := scpUpload(c2, "grande", "grande", make([]byte, 1001)); err == nil {
		t.Error("tope por archivo no aplicado")
	}
	c3 := mustDial(t, s.addr, r)
	if err := scpUpload(c3, "otro", "otro", make([]byte, 600)); err != nil { // 501 + 600 = 1101 < 1500
		t.Errorf("dentro del tope total: %v", err)
	}
	c4 := mustDial(t, s.addr, r)
	if err := scpUpload(c4, "otro2", "otro2", make([]byte, 600)); err == nil {
		t.Error("tope total no aplicado") // 1101 + 600 > 1500
	}
	if _, err := os.Stat(filepath.Join(recv, "otro2")); err == nil {
		t.Error("quedó un archivo sobre el tope total")
	}
	// Modos por separado.
	sw, rw := startCfg(t, Config{Proto: "scp", Write: true, RecvDir: t.TempDir()})
	if _, err := scpDownload(mustDial(t, sw.addr, rw), "img.bin"); err == nil {
		t.Error("lectura habilitada sin pedirla")
	}
	p, _ := image(t, "a.bin", 10)
	sr, rr := startCfg(t, Config{Proto: "scp", Files: []string{p}})
	if err := scpUpload(mustDial(t, sr.addr, rr), "x", "x", []byte("1")); err == nil {
		t.Error("escritura habilitada sin pedirla")
	}
}

func TestParseSCP(t *testing.T) {
	ok := map[string][2]string{
		"scp -t cfg.txt":         {"t", "cfg.txt"},
		"scp -t -- cfg.txt":      {"t", "cfg.txt"},
		"scp -f /a.bin":          {"f", "/a.bin"},
		"scp -v -t .":            {"t", "."},
		"scp -tv 'r1 .cfg'":      {"", ""},
		"scp -pt \"x.bin\"":      {"t", "x.bin"},
		"scp -d -t /flash/x.bin": {"t", "/flash/x.bin"},
	}
	for in, want := range ok {
		m, p, err := parseSCP(in)
		if want[0] == "" {
			if err == nil {
				t.Errorf("%q debió rechazarse", in)
			}
			continue
		}
		if err != nil || string(m) != want[0] || p != want[1] {
			t.Errorf("%q = %c %q %v", in, m, p, err)
		}
	}
	for _, in := range []string{"", "scp", "scp -t", "ls", "scp -r -t x", "scp -t -f x", "scp -t x y", "scp -t x;id", "scp -t $(id)", "scp -t `id`", "scp -S sh -t x",
		"/usr/bin/scp -t x", "scp -t 'a'b", "scp  -t x", "scp -t \x00", "scp -t a\nb", "scp -", "scp x -t", "scp -o ProxyCommand=id -t x"} {
		if m, p, err := parseSCP(in); err == nil {
			t.Errorf("%q aceptado: %c %q", in, m, p)
		}
	}
}

func FuzzParseSCP(f *testing.F) {
	for _, s := range []string{"scp -t x", "scp -f /a", "scp -v -t -- x", "", "scp -", "scp -t 'a b'"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		m, p, err := parseSCP(in)
		if err != nil {
			return
		}
		if m != 't' && m != 'f' || p == "" || strings.ContainsAny(p, "\n\x00;|&$`") {
			t.Fatalf("aceptó algo peligroso: %q -> %c %q", in, m, p)
		}
	})
}

var _ = net.IPv4

// Una subida SFTP que se corta (el cliente cae o el servidor se detiene) sin cerrar el
// handle no deja un archivo parcial dado por bueno: se borra y la transferencia es fallida.
func TestSFTPPartialUploadDiscarded(t *testing.T) {
	for _, how := range []string{"cliente cae", "servidor se detiene"} {
		t.Run(how, func(t *testing.T) {
			recv := t.TempDir()
			s, r := startCfg(t, Config{Proto: "sftp", Write: true, RecvDir: recv})
			ssh1 := mustDial(t, s.addr, r)
			cl, err := sftp.NewClient(ssh1)
			if err != nil {
				t.Fatal(err)
			}
			w, err := cl.Create("/parcial.bin")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(bytes.Repeat([]byte("x"), 100000)); err != nil {
				t.Fatal(err)
			}
			if how == "cliente cae" {
				ssh1.Close() // sin w.Close(): el handle queda abierto
			} else {
				s.stop()
			}
			x := s.waitTransfers(t, 1)[0]
			if x.Result == "ok" || x.Error == "" {
				t.Fatalf("subida cortada dada por buena: %+v", x)
			}
			if _, err := os.Stat(filepath.Join(recv, "parcial.bin")); err == nil {
				t.Fatal("quedó el archivo parcial")
			}
		})
	}
}

// ---- algoritmos antiguos: apagados por omisión, lista explícita a pedido ----

func dialWith(addr string, r Ready, mod func(*ssh.ClientConfig)) error {
	cfg := &ssh.ClientConfig{User: r.User, Auth: []ssh.AuthMethod{ssh.Password(r.Pass)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second}
	mod(cfg)
	c, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		c.Close()
	}
	return err
}

func TestSSHLegacyAlgorithmList(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	old := map[string]func(*ssh.ClientConfig){
		"kex group14-sha1":   func(c *ssh.ClientConfig) { c.KeyExchanges = []string{ssh.InsecureKeyExchangeDH14SHA1} },
		"cifrado aes128-cbc": func(c *ssh.ClientConfig) { c.Ciphers = []string{ssh.InsecureCipherAES128CBC} },
		"cifrado 3des-cbc":   func(c *ssh.ClientConfig) { c.Ciphers = []string{ssh.InsecureCipherTripleDESCBC} },
		"mac hmac-sha1":      func(c *ssh.ClientConfig) { c.Ciphers, c.MACs = []string{ssh.CipherAES128CTR}, []string{ssh.HMACSHA1} }, // con AEAD el MAC no se negocia,
		"llave ssh-rsa":      func(c *ssh.ClientConfig) { c.HostKeyAlgorithms = []string{ssh.KeyAlgoRSA} },
	}
	never := map[string]func(*ssh.ClientConfig){
		"kex group1-sha1":    func(c *ssh.ClientConfig) { c.KeyExchanges = []string{ssh.InsecureKeyExchangeDH1SHA1} },
		"kex gex-sha1":       func(c *ssh.ClientConfig) { c.KeyExchanges = []string{ssh.InsecureKeyExchangeDHGEXSHA1} },
		"cifrado arcfour":    func(c *ssh.ClientConfig) { c.Ciphers = []string{ssh.InsecureCipherRC4} },
		"cifrado arcfour128": func(c *ssh.ClientConfig) { c.Ciphers = []string{ssh.InsecureCipherRC4128} },
		"cifrado arcfour256": func(c *ssh.ClientConfig) { c.Ciphers = []string{ssh.InsecureCipherRC4256} },
		"mac hmac-sha1-96": func(c *ssh.ClientConfig) {
			c.Ciphers, c.MACs = []string{ssh.CipherAES128CTR}, []string{ssh.InsecureHMACSHA196}
		},
	}
	// Apagado (por omisión): ninguno de los antiguos entra, uno por uno.
	s, r := startCfg(t, Config{Proto: "scp", Files: []string{p}})
	for name, mod := range old {
		if err := dialWith(s.addr, r, mod); err == nil {
			t.Errorf("modo moderno aceptó %s", name)
		}
	}
	if err := dialWith(s.addr, r, func(*ssh.ClientConfig) {}); err != nil {
		t.Fatalf("cliente moderno: %v", err)
	}
	// A pedido: solo los cuatro de IOS 15.x (y la llave ssh-rsa); nada de group1, RC4 ni hmac-sha1-96.
	s2, r2 := startCfg(t, Config{Proto: "scp", Files: []string{p}, Legacy: true})
	for name, mod := range old {
		if err := dialWith(s2.addr, r2, mod); err != nil {
			t.Errorf("--legacy-ssh rechazó %s: %v", name, err)
		}
	}
	for name, mod := range never {
		if err := dialWith(s2.addr, r2, mod); err == nil {
			t.Errorf("--legacy-ssh aceptó %s", name)
		}
	}
}

// Lo mismo para el handshake SSH: bytes sueltos no renuevan el plazo de autenticación.
func TestSSHAuthWindowIsAbsolute(t *testing.T) {
	old := authWindow
	authWindow = 400 * time.Millisecond
	t.Cleanup(func() { authWindow = old })
	s, _ := startCfg(t, Config{Proto: "scp", Files: []string{mustImage(t)}})
	c, err := net.Dial("tcp", s.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	for time.Since(start) < 4*time.Second {
		if _, err := c.Write([]byte("S")); err != nil { // una versión que nunca termina
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("el servidor aguantó %v de handshake a cuentagotas", d)
	}
}
