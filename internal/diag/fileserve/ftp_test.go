package fileserve

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

type ftpC struct {
	t  *testing.T
	c  net.Conn
	tp *textproto.Conn
}

func ftpDial(t *testing.T, addr string) *ftpC {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	t.Cleanup(func() { c.Close() })
	f := &ftpC{t: t, c: c, tp: textproto.NewConn(c)}
	f.expect(220)
	return f
}

func (f *ftpC) cmd(code int, format string, a ...any) string {
	f.t.Helper()
	if err := f.tp.PrintfLine(format, a...); err != nil {
		f.t.Fatal(err)
	}
	return f.expect(code)
}

func (f *ftpC) expect(code int) string {
	f.t.Helper()
	_, msg, err := f.tp.ReadResponse(code)
	if err != nil {
		f.t.Fatalf("esperaba %d: %v", code, err)
	}
	return msg
}

func (f *ftpC) login(r Ready) {
	f.t.Helper()
	f.cmd(331, "USER %s", r.User)
	f.cmd(230, "PASS %s", r.Pass)
}

var pasvRe = regexp.MustCompile(`\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)`)

func (f *ftpC) pasv() net.Conn {
	f.t.Helper()
	m := pasvRe.FindStringSubmatch(f.cmd(227, "PASV"))
	if m == nil {
		f.t.Fatal("PASV sin dirección")
	}
	p1, _ := strconv.Atoi(m[5])
	p2, _ := strconv.Atoi(m[6])
	dc, err := net.Dial("tcp", fmt.Sprintf("%s.%s.%s.%s:%d", m[1], m[2], m[3], m[4], p1*256+p2))
	if err != nil {
		f.t.Fatal(err)
	}
	dc.SetDeadline(time.Now().Add(10 * time.Second))
	f.t.Cleanup(func() { dc.Close() })
	return dc
}

func TestFTPServer(t *testing.T) {
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "a.bin"), []byte("contenido A"), 0o600)
	os.Mkdir(filepath.Join(pub, "sub"), 0o700)
	os.Symlink("/etc/hostname", filepath.Join(pub, "enlace"))
	recv := t.TempDir()
	s, r := startCfg(t, Config{Proto: "ftp", FromDir: pub, Write: true, RecvDir: recv, MaxFile: 1000, MaxTotal: 1500})
	f := ftpDial(t, s.addr)
	// Sin sesión no se hace nada.
	f.cmd(530, "RETR a.bin")
	f.cmd(331, "USER %s", r.User)
	f.cmd(530, "PASS mala")
	f.login(r)
	f.cmd(257, "PWD")
	f.cmd(250, "CWD /")
	f.cmd(550, "CWD /etc")
	f.cmd(200, "TYPE I")
	f.cmd(502, "PORT 127,0,0,1,4,1")
	f.cmd(502, "EPRT |1|127.0.0.1|1025|")
	if got := f.cmd(213, "SIZE a.bin"); got != "11" {
		t.Fatalf("SIZE = %q", got)
	}
	f.cmd(550, "SIZE sub/x")
	f.cmd(550, "SIZE enlace")
	// RETR
	dc := f.pasv()
	f.cmd(150, "RETR a.bin")
	b, _ := io.ReadAll(dc)
	f.expect(226)
	if string(b) != "contenido A" {
		t.Fatalf("RETR = %q", b)
	}
	for _, name := range []string{"enlace", "sub", "../a.bin", "/etc/passwd", "nada", "sub/x"} {
		f.cmd(550, "RETR %s", name)
	}
	// Listado: solo lo publicado.
	dc = f.pasv()
	f.cmd(150, "LIST")
	b, _ = io.ReadAll(dc)
	f.expect(226)
	if !strings.Contains(string(b), "a.bin") || strings.Contains(string(b), "enlace") || strings.Contains(string(b), "sub") {
		t.Fatalf("LIST = %q", b)
	}
	// STOR
	data := bytes.Repeat([]byte("hostname R1\n"), 50)
	dc = f.pasv()
	f.cmd(150, "STOR running-config")
	dc.Write(data)
	dc.Close()
	f.expect(226)
	if got, _ := os.ReadFile(filepath.Join(recv, "running-config")); !bytes.Equal(got, data) {
		t.Fatal("STOR: contenido distinto")
	}
	if st, _ := os.Stat(filepath.Join(recv, "running-config")); st.Mode().Perm() != 0o600 {
		t.Fatalf("permisos %v", st.Mode())
	}
	f.pasv()
	f.cmd(550, "STOR running-config") // no sobrescribe
	// Nombre con ruta: solo la base, dentro de la carpeta.
	dc = f.pasv()
	f.cmd(150, "STOR ../../x/crashinfo")
	dc.Write([]byte("1"))
	dc.Close()
	f.expect(226)
	if _, err := os.Stat(filepath.Join(recv, "crashinfo")); err != nil {
		t.Fatal("STOR con ruta no cayó en la carpeta")
	}
	// Tope por archivo (1000) en vuelo y tope total.
	dc = f.pasv()
	f.cmd(150, "STOR grande")
	dc.Write(make([]byte, 1200))
	dc.Close()
	f.expect(552)
	if _, err := os.Stat(filepath.Join(recv, "grande")); err == nil {
		t.Fatal("quedó un archivo sobre el tope")
	}
	dc = f.pasv()
	f.cmd(150, "STOR otro")
	dc.Write(make([]byte, 900)) // 600 + 1 + 900 > 1500
	dc.Close()
	f.expect(552)
	// Modificar lo ajeno: nada.
	for _, c := range []string{"DELE a.bin", "RNFR a.bin", "MKD x", "RMD sub", "APPE a.bin", "SITE chmod 777 a.bin"} {
		f.cmd(550, "%s", c)
	}
	if _, err := os.Stat(filepath.Join(pub, "a.bin")); err != nil {
		t.Fatal("se borró un publicado")
	}
	f.cmd(221, "QUIT")
}

func TestFTPDataConnOnlyFromClientIP(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	s, r := startCfg(t, Config{Proto: "ftp", Files: []string{p}})
	f := ftpDial(t, s.addr)
	f.login(r)
	f.cmd(200, "TYPE I")
	dc := f.pasv() // 127.0.0.1 es el cliente: entra
	f.cmd(150, "RETR a.bin")
	if b, _ := io.ReadAll(dc); len(b) != 10 {
		t.Fatal("RETR")
	}
	f.expect(226)
	// EPSV
	m := regexp.MustCompile(`\|\|\|(\d+)\|`).FindStringSubmatch(f.cmd(229, "EPSV"))
	if m == nil {
		t.Fatal("EPSV")
	}
	dc2, err := net.Dial("tcp", "127.0.0.1:"+m[1])
	if err != nil {
		t.Fatal(err)
	}
	defer dc2.Close()
	f.cmd(150, "RETR a.bin")
	io.ReadAll(dc2)
	f.expect(226)
	// RETR sin PASV
	f.cmd(425, "RETR a.bin")
	// Un tercero (otra IP de origen) no puede tomar la conexión de datos.
	m = pasvRe.FindStringSubmatch(f.cmd(227, "PASV"))
	addr := fmt.Sprintf("%s.%s.%s.%s:%d", m[1], m[2], m[3], m[4], atoi(m[5])*256+atoi(m[6]))
	f.cmd(150, "RETR a.bin") // desde aquí el servidor espera la conexión de datos
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}, Timeout: 2 * time.Second}
	intruder, err := d.Dial("tcp", addr)
	if err != nil {
		t.Skip("no se puede originar desde 127.0.0.2:", err)
	}
	defer intruder.Close()
	intruder.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := intruder.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("el intruso no fue desconectado: %v", err)
	}
	dc3, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer dc3.Close()
	if b, _ := io.ReadAll(dc3); len(b) != 10 {
		t.Fatal("el cliente legítimo no recibió el archivo")
	}
	f.expect(226)
}

func TestFTPPassiveRange(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	// Rango de dos puertos: la tercera conexión pasiva abierta a la vez ya no cabe.
	s, r := startCfg(t, Config{Proto: "ftp", Files: []string{p}, PassivePorts: [2]uint16{47100, 47101}})
	f := ftpDial(t, s.addr)
	f.login(r)
	m := pasvRe.FindStringSubmatch(f.cmd(227, "PASV"))
	port, _ := strconv.Atoi(m[5])
	port = port*256 + atoi(m[6])
	if port < 47100 || port > 47101 {
		t.Fatalf("puerto pasivo %d fuera del rango", port)
	}
	// Otro cliente toma el otro puerto; un tercero se queda sin.
	f2 := ftpDial(t, s.addr)
	f2.login(r)
	f2.cmd(227, "PASV")
	f3 := ftpDial(t, s.addr)
	f3.login(r)
	f3.cmd(425, "PASV")
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func TestFTPAuthLimitsAndAllowList(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	s, r := startCfg(t, Config{Proto: "ftp", Files: []string{p}})
	f := ftpDial(t, s.addr)
	f.cmd(331, "USER %s", r.User)
	f.cmd(530, "PASS x1")
	f.cmd(331, "USER %s", r.User)
	f.cmd(530, "PASS x2")
	f.cmd(331, "USER %s", r.User)
	f.tp.PrintfLine("PASS x3")
	f.expect(421) // cierra al tercer fallo
	// Líneas absurdas no tumban nada.
	g := ftpDial(t, s.addr)
	g.tp.PrintfLine("%s", strings.Repeat("A", 5000))
	g.c.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.Copy(io.Discard, g.c) // el servidor corta la conexión
	h := ftpDial(t, s.addr)
	h.cmd(500, "\x01\x02")
	h.cmd(500, "A")
	h.cmd(530, "RETR a.bin")
	// Lista de IP.
	s2, r2 := startCfg(t, Config{Proto: "ftp", Files: []string{p}, Allow: []netip.Addr{netip.MustParseAddr("10.9.9.9")}})
	c, err := net.Dial("tcp", s2.addr)
	if err == nil {
		c.SetReadDeadline(time.Now().Add(time.Second))
		if n, _ := c.Read(make([]byte, 10)); n > 0 {
			t.Fatal("saludó a un origen no permitido")
		}
		c.Close()
	}
	_ = r2
}

func TestFTPReadWriteSeparate(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	s, r := startCfg(t, Config{Proto: "ftp", Files: []string{p}})
	f := ftpDial(t, s.addr)
	f.login(r)
	f.cmd(550, "STOR x")
	s2, r2 := startCfg(t, Config{Proto: "ftp", Write: true, RecvDir: t.TempDir()})
	f2 := ftpDial(t, s2.addr)
	f2.login(r2)
	f2.cmd(550, "RETR a.bin")
	dc := f2.pasv()
	f2.cmd(150, "LIST") // lectura apagada: listado vacío
	b, _ := io.ReadAll(dc)
	f2.expect(226)
	if len(b) != 0 {
		t.Fatalf("LIST sin lectura = %q", b)
	}
}

func TestParseFTP(t *testing.T) {
	for in, want := range map[string][2]string{
		"USER mac\r\n": {"USER", "mac"}, "pass  x y": {"PASS", "x y"}, "QUIT": {"QUIT", ""}, "retr a.bin\r": {"RETR", "a.bin"},
	} {
		c, a, err := parseFTP(in)
		if err != nil || c != want[0] || a != want[1] {
			t.Errorf("%q = %q %q %v", in, c, a, err)
		}
	}
	for _, in := range []string{"", "A", "ABCDE x", "US3R x", "RETR a\x00b", "RETR a\x01", strings.Repeat("A", 600), "RETR " + strings.Repeat("a", 600), " USER x"} {
		if c, a, err := parseFTP(in); err == nil {
			t.Errorf("%q aceptado: %q %q", in, c, a)
		}
	}
}

func FuzzParseFTP(f *testing.F) {
	for _, s := range []string{"USER mac", "RETR a.bin\r\n", "", "PASV", "\x00", "EPSV ALL"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		c, a, err := parseFTP(in)
		if err != nil {
			return
		}
		if len(c) < 3 || len(c) > 4 || strings.ToUpper(c) != c || strings.ContainsAny(c+a, "\r\n\x00") {
			t.Fatalf("salida inconsistente: %q -> %q %q", in, c, a)
		}
	})
}

func TestHints(t *testing.T) {
	r := Ready{Addr: "10.0.0.5:2121", User: "mac", Pass: "pw123", Fingerprints: []string{"SHA256:aa", "SHA256:bb"}}
	for _, tc := range []struct {
		proto string
		write bool
		want  []string
	}{
		{"ftp", true, []string{"ip ftp username mac", "ip ftp passive", "copy ftp://10.0.0.5/a.bin flash:", "copy running-config ftp://10.0.0.5/", "tcp dport 21 redirect to :2121", "setcap cap_net_bind_service"}},
		{"scp", true, []string{"copy scp://mac@10.0.0.5/a.bin flash:", "copy running-config scp://mac@10.0.0.5/", "SHA256:aa", "tcp dport 22 redirect to :2121"}},
		{"sftp", false, []string{"copy sftp://mac@10.0.0.5/a.bin flash:", "tcp dport 22 redirect to :2121"}},
		{"tftp", true, []string{"copy running-config tftp://10.0.0.5/", "udp dport 69 redirect to :2121"}},
		{"http", false, []string{"copy http://10.0.0.5:2121/a.bin flash:"}},
	} {
		h := ServerHint(Config{Proto: tc.proto, Write: tc.write}, r, []string{"a.bin"})
		for _, w := range tc.want {
			if !strings.Contains(h, w) {
				t.Errorf("%s: falta %q en\n%s", tc.proto, w, h)
			}
		}
		if (tc.proto == "http" || tc.write == false) && strings.Contains(h, "copy running-config") {
			t.Errorf("%s: ofrece escribir sin escritura\n%s", tc.proto, h)
		}
	}
	if h := ServerHint(Config{Proto: "scp"}, Ready{Addr: "0.0.0.0:2222"}, []string{"a"}); !strings.Contains(h, "IP-DE-ESTA-MÁQUINA") {
		t.Error(h)
	}
	if got := RedirectHint("http", "10.0.0.5", 8080); got != "" {
		t.Errorf("http no tiene puerto privilegiado: %q", got)
	}
}

// Detener el servidor corta la transferencia en curso: Serve vuelve rápido, el archivo
// parcial se borra y queda auditado como fallido (no espera a los 30 s de inactividad).
func TestFTPStopCutsTransferInFlight(t *testing.T) {
	recv := t.TempDir()
	s, r := startCfg(t, Config{Proto: "ftp", Write: true, RecvDir: recv})
	f := ftpDial(t, s.addr)
	f.login(r)
	f.cmd(200, "TYPE I")
	dc := f.pasv()
	f.cmd(150, "STOR parcial.bin")
	if _, err := dc.Write(bytes.Repeat([]byte("x"), 5000)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // que el servidor ya haya empezado a escribir
	s.stop()
	select {
	case err := <-s.done:
		s.done <- err // el cierre de la prueba también lo lee
	case <-time.After(time.Second):
		t.Fatal("Serve no volvió en 1 s tras detener")
	}
	if _, err := os.Stat(filepath.Join(recv, "parcial.bin")); err == nil {
		t.Fatal("quedó el archivo parcial")
	}
	if x := s.transfers(); len(x) != 1 || x[0].Result == "ok" || x[0].Error == "" {
		t.Fatalf("transferencias = %+v", x)
	}
}

// Lo mismo mientras el servidor espera la conexión de datos (STOR sin abrirla).
func TestFTPStopWhileWaitingForDataConn(t *testing.T) {
	recv := t.TempDir()
	s, r := startCfg(t, Config{Proto: "ftp", Write: true, RecvDir: recv})
	f := ftpDial(t, s.addr)
	f.login(r)
	f.cmd(227, "PASV") // sin conectarse al puerto de datos
	f.cmd(150, "STOR esperando.bin")
	s.stop()
	select {
	case err := <-s.done:
		s.done <- err
	case <-time.After(time.Second):
		t.Fatal("Serve no volvió en 1 s esperando la conexión de datos")
	}
	if _, err := os.Stat(filepath.Join(recv, "esperando.bin")); err == nil {
		t.Fatal("quedó el archivo vacío")
	}
}

// El plazo para autenticarse es absoluto: NOOP o USER sin fin no lo renuevan.
func TestFTPAuthWindowIsAbsolute(t *testing.T) {
	old := authWindow
	authWindow = 400 * time.Millisecond
	t.Cleanup(func() { authWindow = old })
	s, _ := startCfg(t, Config{Proto: "ftp", Files: []string{mustImage(t)}})
	f := ftpDial(t, s.addr)
	start := time.Now()
	for time.Since(start) < 3*time.Second {
		if err := f.tp.PrintfLine("NOOP"); err != nil {
			break
		}
		if _, _, err := f.tp.ReadResponse(200); err != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("el servidor aguantó %v de NOOP sin autenticar", d)
	}
}

func mustImage(t *testing.T) string { p, _ := image(t, "a.bin", 10); return p }
