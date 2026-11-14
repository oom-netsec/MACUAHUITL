package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"crypto/ed25519"
	"crypto/rand"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	"io"
	"sync/atomic"
)

var rawNet = Net{
	Dial: func(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(host, fmt.Sprint(port)))
	},
	Packet: func(ctx context.Context, host string, port uint16) (net.PacketConn, *net.UDPAddr, error) {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		return pc, &net.UDPAddr{IP: net.ParseIP(host), Port: int(port)}, err
	},
}

func startSrv(t *testing.T, c fileserve.Config) fileserve.Ready {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan fileserve.Ready, 1)
	done := make(chan error, 1)
	c.Addr = "127.0.0.1:0"
	if c.Proto == "tftp" && c.Write && len(c.Allow) == 0 { // escribir por TFTP exige lista de IP
		c.Allow = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	c.OnReady = func(r fileserve.Ready) { ready <- r }
	go func() { done <- fileserve.Serve(ctx, c) }()
	select {
	case r := <-ready:
		t.Cleanup(func() { cancel(); <-done })
		return r
	case err := <-done:
		t.Fatal(err)
	}
	return fileserve.Ready{}
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// reqFor arma la petición para un esquema contra el servidor de pruebas.
func reqFor(t *testing.T, scheme string, r fileserve.Ready, file string) Request {
	t.Helper()
	req := Request{Net: rawNet, URL: &url.URL{Scheme: scheme, Host: r.Addr, Path: "/" + file}, User: r.User, Pass: r.Pass}
	if scheme == "scp" || scheme == "sftp" {
		req.SSH = func(ctx context.Context) (SSHSession, error) {
			c, err := ssh.Dial("tcp", r.Addr, &ssh.ClientConfig{User: r.User, Auth: []ssh.AuthMethod{ssh.Password(r.Pass)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
			return clientSession{c}, err
		}
	}
	return req
}

func TestRoundTripAllProtocols(t *testing.T) {
	data := bytes.Repeat([]byte("interface Gi0/1\n shutdown\n"), 700) // varios bloques
	for _, proto := range []string{"tftp", "ftp", "scp", "sftp"} {
		t.Run(proto, func(t *testing.T) {
			pub, recv, dest := t.TempDir(), t.TempDir(), t.TempDir()
			os.WriteFile(filepath.Join(pub, "r1.cfg"), data, 0o600)
			r := startSrv(t, fileserve.Config{Proto: proto, FromDir: pub, Write: true, RecvDir: recv})
			// Put: del cliente al servidor (copy running-config <proto>:).
			up := reqFor(t, proto, r, "subida.cfg")
			up.FromDir, up.Name = pub, "r1.cfg"
			res, err := Upload(context.Background(), up)
			if err != nil {
				t.Fatal(err)
			}
			if res.Bytes != int64(len(data)) || res.SHA256 != sum(data) {
				t.Fatalf("put: %+v", res)
			}
			if got, _ := os.ReadFile(filepath.Join(recv, "subida.cfg")); !bytes.Equal(got, data) {
				t.Fatalf("el servidor recibió %d bytes distintos", len(got))
			}
			// Get: del servidor a la carpeta de destino.
			g := reqFor(t, proto, r, "r1.cfg")
			g.DestDir, g.WantSHA256 = dest, strings.ToUpper(sum(data))
			res, err = Download(context.Background(), g)
			if err != nil {
				t.Fatal(err)
			}
			st, _ := os.Stat(res.Path)
			if res.Path != filepath.Join(dest, "r1.cfg") || res.Bytes != int64(len(data)) || res.SHA256 != sum(data) || res.Verified != "ok" || len(res.MD5) != 32 || st.Mode().Perm() != 0o600 {
				t.Fatalf("get: %+v (%v)", res, st.Mode())
			}
			// Nunca sobrescribe.
			if _, err := Download(context.Background(), g); err == nil || !strings.Contains(err.Error(), "ya existe") {
				t.Fatalf("segunda descarga: %v", err)
			}
			if got, _ := os.ReadFile(res.Path); !bytes.Equal(got, data) {
				t.Fatal("el existente cambió")
			}
		})
	}
}

func TestDownloadHTTPAndTLS(t *testing.T) {
	data := []byte("imagen http")
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "i.bin"), data, 0o600)
	r := startSrv(t, fileserve.Config{Proto: "http", FromDir: pub})
	dest := t.TempDir()
	g := reqFor(t, "http", r, "i.bin")
	g.DestDir, g.WantSHA256 = dest, sum(data)
	if res, err := Download(context.Background(), g); err != nil || res.Verified != "ok" {
		t.Fatalf("http: %+v %v", res, err)
	}
	if g.URL.Path = "/no-existe"; true {
		if _, err := Download(context.Background(), g); err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("404: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "no-existe")); err == nil {
		t.Fatal("un 404 dejó un archivo")
	}
	// HTTPS: el certificado autofirmado se rechaza salvo --insecure.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(data) }))
	defer ts.Close()
	u, _ := url.Parse(ts.URL + "/x.bin")
	tls := Request{Net: rawNet, URL: u, DestDir: t.TempDir()}
	if _, err := Download(context.Background(), tls); err == nil {
		t.Fatal("aceptó un certificado no verificable")
	}
	tls.Insecure = true
	if res, err := Download(context.Background(), tls); err != nil || res.SHA256 != sum(data) {
		t.Fatalf("insecure: %+v %v", res, err)
	}
	// Sin resumen coincidente se descarta el archivo.
	bad := Request{Net: rawNet, URL: u, Insecure: true, DestDir: t.TempDir(), WantSHA256: strings.Repeat("0", 64)}
	if res, err := Download(context.Background(), bad); err == nil || res.Verified != "distinto" {
		t.Fatalf("hash distinto: %+v %v", res, err)
	}
	if ents, _ := os.ReadDir(bad.DestDir); len(ents) != 0 {
		t.Fatal("quedó un archivo que no coincide con el hash")
	}
	// Redirección hacia donde no se autorizó: la salida la niega Net.Dial.
	denied := errors.New("destino no autorizado")
	rd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://192.0.2.1:9/x", http.StatusFound)
	}))
	defer rd.Close()
	u2, _ := url.Parse(rd.URL + "/a")
	allowed := rd.Listener.Addr().String()
	guarded := Net{Dial: func(ctx context.Context, n, h string, p uint16) (net.Conn, error) {
		if net.JoinHostPort(h, fmt.Sprint(p)) != allowed {
			return nil, denied
		}
		return rawNet.Dial(ctx, n, h, p)
	}}
	if _, err := Download(context.Background(), Request{Net: guarded, URL: u2, DestDir: t.TempDir()}); !errors.Is(err, denied) {
		t.Fatalf("redirección a destino ajeno: %v", err)
	}
}

func TestLimitsAndDestination(t *testing.T) {
	data := make([]byte, 5000)
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "g.bin"), data, 0o600)
	for _, proto := range []string{"tftp", "ftp", "scp", "sftp", "http"} {
		r := startSrv(t, fileserve.Config{Proto: proto, FromDir: pub})
		dest := t.TempDir()
		g := reqFor(t, proto, r, "g.bin")
		g.DestDir, g.MaxBytes = dest, 1000
		if _, err := Download(context.Background(), g); err == nil {
			t.Errorf("%s: pasó el tope de tamaño", proto)
		}
		if ents, _ := os.ReadDir(dest); len(ents) != 0 {
			t.Errorf("%s: quedó un archivo sobre el tope: %v", proto, ents)
		}
	}
	// Carpeta de destino: enlace, sensible o inexistente.
	r := startSrv(t, fileserve.Config{Proto: "http", FromDir: pub})
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "l")
	os.Symlink(real, link)
	for _, d := range []string{link, "/etc", "/usr/share", "relativa", filepath.Join(real, "no-existe")} {
		g := reqFor(t, "http", r, "g.bin")
		g.DestDir = d
		if _, err := Download(context.Background(), g); err == nil {
			t.Errorf("destino %q aceptado", d)
		}
	}
	// El nombre local se sanea: sin rutas ni "..".
	g := reqFor(t, "http", r, "g.bin")
	g.DestDir, g.Name = real, "../../escape.bin"
	res, err := Download(context.Background(), g)
	if err != nil || res.Path != filepath.Join(real, "escape.bin") {
		t.Fatalf("%+v %v", res, err)
	}
	for _, bad := range []string{"..", "", "a\x00b"} {
		g.Name = bad
		if bad == "" {
			g.URL.Path = "/"
		}
		if _, err := Download(context.Background(), g); err == nil {
			t.Errorf("nombre local %q aceptado", bad)
		}
	}
	// Tiempo: un servidor que no contesta no cuelga el cliente.
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	hole := Request{Net: rawNet, URL: &url.URL{Scheme: "tftp", Host: pc.LocalAddr().String(), Path: "/x"}, DestDir: t.TempDir(), Timeout: 800 * time.Millisecond}
	start := time.Now()
	if _, err := Download(context.Background(), hole); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("timeout: %v tras %s", err, time.Since(start))
	}
	if ents, _ := os.ReadDir(hole.DestDir); len(ents) != 0 {
		t.Fatal("el timeout dejó un archivo")
	}
	if _, err := Download(context.Background(), Request{Net: rawNet, URL: hole.URL, DestDir: real, Timeout: 5 * time.Hour}); err == nil {
		t.Error("timeout de 5 h aceptado")
	}
}

func TestUploadSourceRules(t *testing.T) {
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "ok"), []byte("1"), 0o600)
	os.Symlink("/etc/hostname", filepath.Join(pub, "enlace"))
	os.Mkdir(filepath.Join(pub, "sub"), 0o700)
	r := startSrv(t, fileserve.Config{Proto: "tftp", Write: true, RecvDir: t.TempDir()})
	for _, tc := range []struct{ dir, name string }{{pub, "enlace"}, {pub, "sub"}, {pub, "../x"}, {pub, "nada"}, {"/etc", "hostname"}, {"rel", "ok"}} {
		u := reqFor(t, "tftp", r, "x")
		u.FromDir, u.Name = tc.dir, tc.name
		if _, err := Upload(context.Background(), u); err == nil {
			t.Errorf("put desde %s/%s aceptado", tc.dir, tc.name)
		}
	}
	u := reqFor(t, "tftp", r, "x")
	u.FromDir, u.Name, u.MaxBytes = pub, "ok", 0
	if _, err := Upload(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	h := reqFor(t, "http", r, "x")
	h.FromDir, h.Name = pub, "ok"
	if _, err := Upload(context.Background(), h); err == nil {
		t.Error("put por HTTP aceptado")
	}
}

func TestRemotePath(t *testing.T) {
	for in, ok := range map[string]bool{"/flash/x.bin": true, "/a_b-c.d": true, "/-oProxyCommand=x": false, "/a b": false, "/a;id": false, "/a$(id)": false, "/": false, "": false, "/dir/": false, "/a'b": false} {
		_, err := remotePath(&url.URL{Path: in})
		if (err == nil) != ok {
			t.Errorf("%q: err=%v", in, err)
		}
	}
	// La UI emite «//» para una ruta absoluta en scp/sftp: remotePath solo quita UNA «/» inicial.
	for u, want := range map[string]string{"scp://h//tmp/x.bin": "/tmp/x.bin", "scp://h/tmp/x.bin": "tmp/x.bin", "sftp://h:2200//flash/c4.bin": "/flash/c4.bin"} {
		pu, _ := url.Parse(u)
		if got, err := remotePath(pu); err != nil || got != want {
			t.Errorf("%s: %q %v", u, got, err)
		}
	}
	for u, want := range map[string]uint16{"tftp://h/x": 69, "ftp://h/x": 21, "scp://h/x": 22, "sftp://h:2222/x": 2222, "http://h/x": 80, "https://h/x": 443} {
		p, _ := url.Parse(u)
		if got, err := Port(p); err != nil || got != want {
			t.Errorf("%s: %d %v", u, got, err)
		}
	}
	if _, err := Port(&url.URL{Scheme: "gopher"}); err == nil {
		t.Error("gopher aceptado")
	}
}

func TestFTPRejectsInjectedLines(t *testing.T) {
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "a"), []byte("1"), 0o600)
	r := startSrv(t, fileserve.Config{Proto: "ftp", FromDir: pub})
	g := reqFor(t, "ftp", r, "a")
	g.DestDir = t.TempDir()
	g.User = "mac\r\nDELE a"
	if _, err := Download(context.Background(), g); err == nil {
		t.Fatal("usuario con salto de línea aceptado")
	}
	g.User, g.Pass = r.User, "x\nQUIT"
	if _, err := Download(context.Background(), g); err == nil {
		t.Fatal("contraseña con salto de línea aceptada")
	}
}

type clientSession struct{ c *ssh.Client }

func (s clientSession) Client() *ssh.Client { return s.c }
func (s clientSession) Close() error        { return s.c.Close() }

// Una redirección de https a http se rechaza: no se baja de nivel (el servidor http no ve ni la petición).
func TestHTTPRedirectDowngradeRejected(t *testing.T) {
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write([]byte("x")) }))
	defer plain.Close()
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/x", http.StatusFound)
	}))
	defer secure.Close()
	u, _ := url.Parse(secure.URL + "/a")
	_, err := Download(context.Background(), Request{Net: rawNet, URL: u, Insecure: true, DestDir: t.TempDir()})
	if err == nil || !strings.Contains(err.Error(), "https a http") {
		t.Fatalf("redirección https→http: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("llegó una petición al servidor http")
	}
	// http → https sí se sigue (sube de nivel).
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secure.URL+"/ok", http.StatusFound)
	}))
	defer up.Close()
	secure.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("bien")) })
	u2, _ := url.Parse(up.URL + "/a")
	if _, err := Download(context.Background(), Request{Net: rawNet, URL: u2, Insecure: true, DestDir: t.TempDir()}); err != nil {
		t.Fatalf("http→https: %v", err)
	}
}

// Un servidor malicioso no nos hace leer sin fin: las líneas de control de FTP y SCP tienen tope.
func TestClientsCapControlLines(t *testing.T) {
	flood := func(w io.Writer) {
		chunk := bytes.Repeat([]byte("A"), 64<<10)
		for range 200 { // 12 MiB sin un solo salto de línea
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}
	t.Run("ftp", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		go func() {
			if c, err := ln.Accept(); err == nil {
				c.Write([]byte("220-")) // saludo multilínea que nunca termina
				flood(c)
				c.Close()
			}
		}()
		u, _ := url.Parse("ftp://" + ln.Addr().String() + "/a")
		_, err := Download(context.Background(), Request{Net: rawNet, URL: u, DestDir: t.TempDir(), Timeout: 20 * time.Second})
		if err == nil || !strings.Contains(err.Error(), "demasiado larga") {
			t.Fatalf("línea de FTP sin tope: %v", err)
		}
	})
	t.Run("scp", func(t *testing.T) {
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		signer, _ := ssh.NewSignerFromKey(key)
		cfg := &ssh.ServerConfig{NoClientAuth: true}
		cfg.AddHostKey(signer)
		go func() {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			for nch := range chans {
				ch, creqs, _ := nch.Accept()
				go func() {
					for r := range creqs {
						r.Reply(true, nil)
						if r.Type == "exec" {
							flood(ch)
							ch.Close()
						}
					}
				}()
			}
		}()
		req := Request{Net: rawNet, URL: &url.URL{Scheme: "scp", Host: ln.Addr().String(), Path: "/a"}, DestDir: t.TempDir(), Timeout: 20 * time.Second}
		req.SSH = func(ctx context.Context) (SSHSession, error) {
			c, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
			return clientSession{c}, err
		}
		_, err := Download(context.Background(), req)
		if err == nil || !strings.Contains(err.Error(), "demasiado larga") {
			t.Fatalf("línea de SCP sin tope: %v", err)
		}
	})
}

type actSession struct {
	clientSession
	n *atomic.Int64
}

func (a actSession) Activity(n int) { a.n.Add(int64(n)) }

// Lo que pasa por los canales de scp/sftp cuenta como actividad de la sesión (keepalive): en una subida
// la actividad son las respuestas del par (lo escrito dentro de la ventana inicial no cuenta; ver keepalive_test.go).
func TestTransferCuentaActividadDeSesion(t *testing.T) {
	data := bytes.Repeat([]byte("x"), 50000)
	for _, proto := range []string{"scp", "sftp"} {
		t.Run(proto, func(t *testing.T) {
			pub, recv, dest := t.TempDir(), t.TempDir(), t.TempDir()
			os.WriteFile(filepath.Join(pub, "r1.cfg"), data, 0o600)
			r := startSrv(t, fileserve.Config{Proto: proto, FromDir: pub, Write: true, RecvDir: recv})
			var n atomic.Int64
			wrap := func(q Request) Request {
				f := q.SSH
				q.SSH = func(ctx context.Context) (SSHSession, error) {
					s, err := f(ctx)
					return actSession{s.(clientSession), &n}, err
				}
				return q
			}
			up := wrap(reqFor(t, proto, r, "subida.cfg"))
			up.FromDir, up.Name = pub, "r1.cfg"
			if _, err := Upload(context.Background(), up); err != nil {
				t.Fatal(err)
			}
			if got := n.Load(); got == 0 || got >= int64(len(data)) {
				t.Fatalf("subida: actividad %d (solo respuestas del par, sin lo escrito)", got)
			}
			n.Store(0)
			g := wrap(reqFor(t, proto, r, "r1.cfg"))
			g.DestDir = dest
			if _, err := Download(context.Background(), g); err != nil {
				t.Fatal(err)
			}
			if got := n.Load(); got < int64(len(data)) {
				t.Fatalf("bajada: actividad %d < %d", got, len(data))
			}
		})
	}
}
