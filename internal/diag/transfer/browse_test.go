package transfer

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
)

func names(es []Entry) string {
	var n []string
	for _, e := range es {
		n = append(n, e.Name)
	}
	return strings.Join(n, ",")
}

func publish(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for n, c := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestBrowseSFTPySCPUsanElSubsistema(t *testing.T) {
	dir := publish(t, map[string]string{"r1.cfg": "hostname r1\n", "r2.cfg": "hostname r22\n", "imagen.bin": strings.Repeat("x", 4096)})
	// scp:// lista por el subsistema SFTP de un servidor que lo tenga (aquí, el de sftp)
	for _, scheme := range []string{"sftp", "scp"} {
		t.Run(scheme, func(t *testing.T) {
			ready := startSrv(t, fileserve.Config{Proto: "sftp", FromDir: dir})
			req := reqFor(t, scheme, ready, "")
			ls, err := Browse(context.Background(), req, "/", 0)
			if err != nil {
				t.Fatal(err)
			}
			if ls.Method != "sftp" || names(ls.Entries) != "imagen.bin,r1.cfg,r2.cfg" || ls.Truncated {
				t.Fatalf("listado = %+v", ls)
			}
			if e := ls.Entries[0]; e.Type != "file" || e.Size != 4096 || e.ModTime.IsZero() || e.Perms == "" || !e.Downloadable {
				t.Fatalf("imagen.bin = %+v", e)
			}
			// el tope de entradas
			ls, err = Browse(context.Background(), req, "/", 2)
			if err != nil || len(ls.Entries) != 2 || !ls.Truncated {
				t.Fatalf("tope: %+v %v", ls, err)
			}
		})
	}
}

// El servidor scp de fileserve solo atiende scp -t/-f: no lista, y la respuesta es el error tipado.
func TestBrowseServidorScpPuroNoLista(t *testing.T) {
	ready := startSrv(t, fileserve.Config{Proto: "scp", FromDir: publish(t, map[string]string{"a.cfg": "x"})})
	_, err := Browse(context.Background(), reqFor(t, "scp", ready, ""), "/", 0)
	var nl *NoListingError
	if !errors.As(err, &nl) {
		t.Fatalf("err = %v", err)
	}
}

// sshSinSFTP es un servidor SSH que acepta la contraseña y rechaza todo subsistema, como un equipo que solo habla scp.
func sshSinSFTP(t *testing.T) (addr string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(key)
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(signer)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, rq, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range rq {
							r.Reply(false, nil) // ni subsistema ni exec
						}
					}()
					_ = ch
				}
			}()
		}
	}()
	return l.Addr().String()
}

func TestBrowseSCPSinSFTPDiceQueNoPermiteListar(t *testing.T) {
	addr := sshSinSFTP(t)
	req := Request{Net: rawNet, URL: &url.URL{Scheme: "scp", Host: addr}}
	req.SSH = func(ctx context.Context) (SSHSession, error) {
		c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.Password("p")}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		return clientSession{c}, err
	}
	_, err := Browse(context.Background(), req, "/", 0)
	var nl *NoListingError
	if !errors.As(err, &nl) || nl.Proto != "scp" || !strings.Contains(err.Error(), "este servidor no permite listar") {
		t.Fatalf("err = %v", err)
	}
	// para sftp, un servidor sin subsistema no es «no lista por diseño»: es un error de conexión
	req.URL.Scheme = "sftp"
	if _, err = Browse(context.Background(), req, "/", 0); err == nil || errors.As(err, &nl) {
		t.Fatalf("sftp sin subsistema: %v", err)
	}
}

func TestBrowseTFTPNoListaYNoMarca(t *testing.T) {
	req := Request{URL: &url.URL{Scheme: "tftp", Host: "10.1.1.1:69"}, Net: Net{
		Dial: func(context.Context, string, string, uint16) (net.Conn, error) {
			t.Fatal("TFTP no debe abrir conexiones")
			return nil, nil
		},
		Packet: func(context.Context, string, uint16) (net.PacketConn, *net.UDPAddr, error) {
			t.Fatal("ni sockets")
			return nil, nil, nil
		},
	}}
	_, err := Browse(context.Background(), req, "/", 0)
	var nl *NoListingError
	if !errors.As(err, &nl) || nl.Proto != "tftp" || !strings.Contains(err.Error(), "este servidor no permite listar") {
		t.Fatalf("err = %v", err)
	}
}

func TestBrowseFTPListComoRespaldo(t *testing.T) {
	// el servidor de fileserve no conoce MLSD (502): se cae a LIST de Unix
	dir := publish(t, map[string]string{"r1.cfg": "hostname r1\n", "r2.cfg": "x"})
	ready := startSrv(t, fileserve.Config{Proto: "ftp", FromDir: dir})
	ls, err := Browse(context.Background(), reqFor(t, "ftp", ready, ""), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Method != "list" || names(ls.Entries) != "r1.cfg,r2.cfg" || ls.Entries[0].Size != 12 {
		t.Fatalf("listado = %+v", ls)
	}
}

// fakeFTP es un servidor FTP mínimo que contesta los listados con lo que se le dé; mlsd="" = no soporta MLSD.
type fakeFTP struct {
	addr       string
	mlsd, list string
	mlsdCode   string // respuesta a MLSD cuando no lo soporta (500 por omisión)
	mu         sync.Mutex
	cmds       []string
}

func newFakeFTP(t *testing.T, mlsd, list string) *fakeFTP {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	f := &fakeFTP{addr: l.Addr().String(), mlsd: mlsd, list: list}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeFTP) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	say := func(s string) { fmt.Fprintf(c, "%s\r\n", s) }
	say("220 listo")
	var dl net.Listener
	for {
		ln, err := br.ReadString('\n')
		if err != nil {
			return
		}
		ln = strings.TrimRight(ln, "\r\n")
		verb, _, _ := strings.Cut(ln, " ")
		f.mu.Lock()
		f.cmds = append(f.cmds, ln)
		f.mu.Unlock()
		switch strings.ToUpper(verb) {
		case "USER":
			say("331 contraseña")
		case "PASS":
			say("230 dentro")
		case "TYPE":
			say("200 ok")
		case "CWD":
			say("250 ok")
		case "EPSV":
			dl, _ = net.Listen("tcp", "127.0.0.1:0")
			say(fmt.Sprintf("229 Entering Extended Passive Mode (|||%d|)", dl.Addr().(*net.TCPAddr).Port))
		case "MLSD", "LIST":
			body := f.list
			if strings.ToUpper(verb) == "MLSD" {
				if f.mlsd == "" {
					say(firstNonEmpty(f.mlsdCode, "500") + " MLSD no entendido")
					if dl != nil {
						dl.Close()
					}
					continue
				}
				body = f.mlsd
			}
			say("150 aquí va")
			dc, err := dl.Accept()
			dl.Close()
			if err != nil {
				return
			}
			dc.Write([]byte(body))
			dc.Close()
			say("226 listo")
		case "QUIT":
			say("221 adiós")
			return
		default:
			say("502 no")
		}
	}
}

func (f *fakeFTP) req() Request {
	return Request{Net: rawNet, URL: &url.URL{Scheme: "ftp", Host: f.addr}}
}

func TestBrowseFTPMLSDyNombresHostiles(t *testing.T) {
	mlsd := "type=cdir;modify=20261106101500; /pub\r\n" +
		"type=dir;modify=20261105083000; carpeta\r\n" +
		"type=file;size=12;modify=20261106101500;perm=r; evil\u202egnp.exe\r\n" +
		"type=file;size=3;modify=20261106101500; ../../etc/passwd\r\n" +
		"type=file;size=7;modify=20261106101500; a.cfg\r\n"
	f := newFakeFTP(t, mlsd, "")
	ls, err := Browse(context.Background(), f.req(), "/pub", 0)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Method != "mlsd" || names(ls.Entries) != "carpeta,a.cfg,evil?gnp.exe" {
		t.Fatalf("listado = %q (%s)", names(ls.Entries), ls.Method)
	}
	if e := ls.Entries[2]; !e.Unsafe || e.Downloadable {
		t.Fatalf("hostil = %+v", e)
	}
	if ls.Entries[0].Type != "dir" {
		t.Fatal("las carpetas van primero")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.Contains(strings.Join(f.cmds, "|"), "CWD /pub") {
		t.Fatalf("órdenes = %v", f.cmds)
	}
}

func TestBrowseFTPListDOS(t *testing.T) {
	f := newFakeFTP(t, "", "11-06-26  10:15AM       <DIR>          backups\r\n11-05-2026  03:07PM            1048576 imagen.bin\r\n")
	ls, err := Browse(context.Background(), f.req(), "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Method != "list" || names(ls.Entries) != "backups,imagen.bin" || ls.Entries[1].Size != 1048576 {
		t.Fatalf("listado = %+v", ls)
	}
}

// Un 4xx a MLSD (p. ej. 425 sin conexión de datos) es un fallo pasajero, no «no soportado»: no se reintenta con LIST.
func TestBrowseFTPNoCaeALISTConUn4xx(t *testing.T) {
	f := newFakeFTP(t, "", "-rw-r--r-- 1 u g 5 Nov  6 10:15 a.cfg\r\n")
	f.mlsdCode = "425"
	if _, err := Browse(context.Background(), f.req(), "", 0); err == nil || !strings.Contains(err.Error(), "425") {
		t.Fatalf("err = %v", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Contains(strings.Join(f.cmds, "|"), "LIST") {
		t.Fatalf("no debió pedir LIST: %v", f.cmds)
	}
}

func TestBrowseFTPTopes(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "type=file;size=%d; f%02d.cfg\r\n", i, i)
	}
	f := newFakeFTP(t, b.String(), "")
	ls, err := Browse(context.Background(), f.req(), "", 10)
	if err != nil || len(ls.Entries) != 10 || !ls.Truncated {
		t.Fatalf("entradas: %d %v %v", len(ls.Entries), ls.Truncated, err)
	}
	// un listado que pasa del tope de bytes se corta y se avisa, sin llenar la memoria
	big := strings.Repeat("type=file;size=1; "+strings.Repeat("n", 200)+"\r\n", 30000) // ≈ 6 MB
	f2 := newFakeFTP(t, big, "")
	ls, err = Browse(context.Background(), f2.req(), "", MaxEntriesCap)
	if err != nil || !ls.Truncated || len(ls.Entries) == 0 {
		t.Fatalf("grande: %d %v %v", len(ls.Entries), ls.Truncated, err)
	}
}

func TestBrowseFTPPlazo(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0") // acepta y calla
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	req := Request{Net: rawNet, URL: &url.URL{Scheme: "ftp", Host: l.Addr().String()}, Timeout: 300 * time.Millisecond}
	start := time.Now()
	if _, err := Browse(context.Background(), req, "", 0); err == nil || time.Since(start) > 3*time.Second {
		t.Fatalf("err = %v tras %v", err, time.Since(start))
	}
}

func TestBrowseRutaInvalida(t *testing.T) {
	f := newFakeFTP(t, "type=file; a\r\n", "")
	for _, p := range []string{"/a\r\nDELE x", "/a\x00b", "/a\u202eb", strings.Repeat("a", 2000)} {
		if _, err := Browse(context.Background(), f.req(), p, 0); err == nil {
			t.Errorf("ruta %q aceptada", p)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.cmds) != 0 {
		t.Fatalf("no debió tocar el servidor: %v", f.cmds)
	}
}

func TestBrowseHTTP(t *testing.T) {
	index := `<html><body><pre><a href="../">Parent</a>
<a href="r1.cfg">r1.cfg</a>   2026-11-06 10:15  1K
<a href="sub/">sub/</a>   2026-11-05 08:30    -
</pre></body></html>`
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		switch r.URL.Path {
		case "/imagenes/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, index)
		case "/json/":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "{}")
		case "/enorme/":
			w.Header().Set("Content-Type", "text/html")
			for i := 0; i < 6<<20; i += 4000 { // pocos enlaces y muchos bytes: corta el tope de bytes, no el de entradas
				fmt.Fprintf(w, "<a href=\"f%d\">f</a>%s\n", i, strings.Repeat(" ", 3980))
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	req := Request{Net: rawNet, URL: &url.URL{Scheme: "http", Host: strings.TrimPrefix(srv.URL, "http://"), Path: "/ignorada", RawQuery: "token=secreto"}}
	ls, err := Browse(context.Background(), req, "/imagenes", 0)
	if err != nil {
		t.Fatal(err)
	}
	if ls.Method != "http" || names(ls.Entries) != "sub,r1.cfg" || ls.Entries[1].Size != 1024 {
		t.Fatalf("listado = %+v", ls)
	}
	if gotPath != "/imagenes/" {
		t.Fatalf("pidió %q: la carpeta termina en / y no lleva query", gotPath)
	}
	if _, err := Browse(context.Background(), req, "/json", 0); err == nil || !strings.Contains(err.Error(), "índice HTML") {
		t.Fatalf("json: %v", err)
	}
	if _, err := Browse(context.Background(), req, "/nada", 0); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404: %v", err)
	}
	ls, err = Browse(context.Background(), req, "/enorme", MaxEntriesCap)
	if err != nil || !ls.Truncated {
		t.Fatalf("enorme: truncado=%v err=%v entradas=%d", ls.Truncated, err, len(ls.Entries))
	}
}

// Decisión del 2026-11-12: en FTP una ruta remota con «/» inicial es absoluta (como en SCP y SFTP) y sin «/» es
// relativa a la carpeta de inicio. En la URL la absoluta va con «//» (remotePath quita solo una «/»).
func TestFTPRutaAbsolutaYRelativa(t *testing.T) {
	f := newFakeFTP(t, "", "")
	for _, c := range []struct{ path, want string }{{"//x/y.cfg", "/x/y.cfg"}, {"/x/y.cfg", "x/y.cfg"}} {
		r := f.req()
		r.URL.Path, r.DestDir = c.path, t.TempDir()
		Download(context.Background(), r) // el servidor falso rechaza el RETR; importa lo que se le pidió
		f.mu.Lock()
		got := strings.Join(f.cmds, "|")
		f.mu.Unlock()
		if !strings.Contains(got, "SIZE "+c.want+"|") && !strings.HasSuffix(got, "SIZE "+c.want) && !strings.Contains(got, "RETR "+c.want) {
			t.Errorf("URL %q: se esperaba pedir %q, se mandó %s", c.path, c.want, got)
		}
		f.mu.Lock()
		f.cmds = nil
		f.mu.Unlock()
	}
	for _, c := range []struct{ path, want string }{{"/x/y", "CWD /x/y"}, {"x/y", "CWD x/y"}} {
		Browse(context.Background(), f.req(), c.path, 0)
		f.mu.Lock()
		got := strings.Join(f.cmds, "|")
		f.cmds = nil
		f.mu.Unlock()
		if !strings.Contains(got, c.want) {
			t.Errorf("listado %q: se esperaba %q, se mandó %s", c.path, c.want, got)
		}
	}
}
