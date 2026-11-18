package fileserve

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys/systest"
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
	pub := realTemp(t)
	os.WriteFile(filepath.Join(pub, "a.bin"), []byte("contenido A"), 0o600)
	os.Mkdir(filepath.Join(pub, "sub"), 0o700)
	os.Symlink("/etc/hostname", filepath.Join(pub, "enlace"))
	recv := realTemp(t)
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
	systest.Private(t, filepath.Join(recv, "running-config"), 0o600)
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
	lo := parLibre(t)
	s, r := startCfg(t, Config{Proto: "ftp", Files: []string{p}, PassivePorts: [2]uint16{lo, lo + 1}})
	f := ftpDial(t, s.addr)
	f.login(r)
	m := pasvRe.FindStringSubmatch(f.cmd(227, "PASV"))
	port, _ := strconv.Atoi(m[5])
	port = port*256 + atoi(m[6])
	if port < int(lo) || port > int(lo)+1 {
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

// parLibre busca dos puertos seguidos libres en 127.0.0.1. Un rango fijo (47100-47101) cae en el rango
// efímero de Linux y fallaba en CI cuando otra conexión lo ocupaba.
func parLibre(t *testing.T) uint16 {
	t.Helper()
	for range 50 {
		// En Windows los puertos efímeros (49152+) se reparten de seguido a las conexiones del cliente de la prueba y se
		// comerían el segundo: se busca fuera de ese rango.
		dir := "127.0.0.1:0"
		if runtime.GOOS == "windows" {
			dir = fmt.Sprintf("127.0.0.1:%d", 20000+rand.IntN(10000))
		}
		a, err := net.Listen("tcp", dir)
		if err != nil {
			if runtime.GOOS == "windows" {
				continue // el puerto al azar pudo estar ocupado
			}
			t.Fatal(err)
		}
		lo := a.Addr().(*net.TCPAddr).Port
		b, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", lo+1))
		a.Close()
		if err == nil {
			b.Close()
			return uint16(lo)
		}
	}
	t.Fatal("sin dos puertos seguidos libres")
	return 0
}

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
	s2, r2 := startCfg(t, Config{Proto: "ftp", Write: true, RecvDir: realTemp(t)})
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
	fijaWindows(t, "linux") // el texto de nft es el de Linux; la pista de Windows la cubre firewall_test.go
	r := Ready{Addr: "10.0.0.5:2121", User: "mac", Pass: "pw123", Fingerprints: []string{"SHA256:aa", "SHA256:bb"}}
	for _, tc := range []struct {
		proto string
		write bool
		want  []string
	}{
		{"ftp", true, []string{"ip ftp username mac", "ip ftp passive", "copy ftp://10.0.0.5/a.bin flash:", "copy running-config ftp://10.0.0.5/", "tcp dport 21 redirect to :2121"}},
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
	recv := realTemp(t)
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
	recv := realTemp(t)
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

// Un rango pasivo que no se puede abrir falla al arrancar (no con «425» en cada PASV).
func TestFTPRangoPasivoOcupadoFallaAlArrancar(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	p := uint16(ln.Addr().(*net.TCPAddr).Port)
	f, _ := image(t, "a.bin", 10)
	err = Serve(context.Background(), Config{Addr: "127.0.0.1:0", Proto: "ftp", Files: []string{f}, PassivePorts: [2]uint16{p, p}})
	var c i18n.Coded
	if !errors.As(err, &c) || c.Reason() != "fileserve.err.port_in_use" {
		t.Fatalf("%v", err)
	}
}

// 43e-9: el 550 de «ya existe» va en inglés en el cable (los equipos no leen español); el registro conserva el motivo del catálogo.
func TestFTPStorExistenteRespondeEnIngles(t *testing.T) {
	recv := realTemp(t)
	if err := os.WriteFile(filepath.Join(recv, "x"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, r := startCfg(t, Config{Proto: "ftp", Write: true, RecvDir: recv})
	f := ftpDial(t, s.addr)
	f.login(r)
	f.pasv()
	got := f.cmd(550, "STOR x")
	if got != "the file already exists" {
		t.Fatalf("550 = %q", got)
	}
}

// 43e-9: nada de lo que el servidor FTP manda al cable va en español (los equipos no lo leen); el registro conserva su motivo.
func TestFTPRespuestasSinEspanol(t *testing.T) {
	es := regexp.MustCompile(`[áéíóúñ¿¡]|\b(archivo|orden|usa|sin|solo|lectura|escritura|transferencia|nombre|conexión|sesión|contraseña|credenciales|intentos|primero|listado|enviando|recibi\w*|adiós|existe|publicado|permitido|soportado|deshabilitad\w*|demasiados|directorio|tipo|error|guardar|abortada|interrumpida|completa|puertos)\b`)
	check := func(f *ftpC, cmd string) {
		t.Helper()
		if err := f.tp.PrintfLine("%s", cmd); err != nil {
			t.Fatal(err)
		}
		line, err := f.tp.ReadLine()
		if err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
		for strings.HasPrefix(line, line[:3]+"-") { // respuesta de varias líneas (FEAT)
			if line, err = f.tp.ReadLine(); err != nil {
				t.Fatal(err)
			}
		}
		if m := es.FindString(line); m != "" {
			t.Errorf("%s -> %q lleva español (%q)", cmd, line, m)
		}
	}
	// solo lectura: sin sesión, credenciales malas, bloqueo y las órdenes de una sesión abierta
	pub, _ := image(t, "a.bin", 10)
	s, r := startCfg(t, Config{Proto: "ftp", Files: []string{pub}})
	f := ftpDial(t, s.addr) // el 220 de bienvenida ya se leyó en ftpDial
	for _, c := range []string{"RETR a.bin", "ZZZ", "PASS x", "USER " + r.User, "PASS mala"} {
		check(f, c)
	}
	f.login(r)
	for _, c := range []string{"SYST", "FEAT", "TYPE I", "TYPE E", "MODE S", "STRU F", "PWD", "CWD /x", "CWD /", "CDUP", "NOOP", "SIZE nada", "SIZE a.bin", "PORT 1,2,3,4,5,6", "EPRT |1|1.2.3.4|5|", "DELE a.bin", "ZZZ", "RETR nada", "RETR a.bin", "STOR x", "LIST", "NLST", "EPSV 2"} {
		check(f, c)
	}

	// el 220 de bienvenida
	c, err := net.DialTimeout("tcp", s.addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if hi, _ := textproto.NewReader(bufio.NewReader(c)).ReadLine(); es.MatchString(hi) {
		t.Errorf("saludo en español: %q", hi)
	}

	// bloqueo por contraseñas malas (421)
	s2, r2 := startCfg(t, Config{Proto: "ftp", Files: []string{pub}})
	f2 := ftpDial(t, s2.addr)
	for range 12 {
		check(f2, "USER "+r2.User)
		if err := f2.tp.PrintfLine("PASS mala"); err != nil {
			break
		}
		l, err := f2.tp.ReadLine()
		if err != nil {
			break
		}
		if es.MatchString(l) {
			t.Errorf("PASS mala -> %q", l)
		}
		if strings.HasPrefix(l, "421") {
			break
		}
	}

	// escritura: sin PASV, nombre existente/ilegal, tope de tamaño, lectura apagada
	recv := realTemp(t)
	os.WriteFile(filepath.Join(recv, "x"), []byte("1"), 0o600)
	s3, r3 := startCfg(t, Config{Proto: "ftp", Write: true, RecvDir: recv, MaxFile: 4})
	f3 := ftpDial(t, s3.addr)
	f3.login(r3)
	check(f3, "STOR y") // sin PASV
	check(f3, "RETR x") // lectura deshabilitada
	f3.pasv()
	check(f3, "STOR x")  // ya existe
	check(f3, "STOR ..") // nombre no permitido
	dc := f3.pasv()
	f3.cmd(150, "STOR grande")
	dc.Write([]byte("123456789"))
	dc.Close()
	l, err := f3.tp.ReadLine()
	if err != nil || es.MatchString(l) {
		t.Errorf("tope de tamaño -> %q %v", l, err)
	}
}
