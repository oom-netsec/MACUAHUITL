package fileserve

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type server struct {
	addr string
	mu   sync.Mutex
	xfer []Transfer
	done chan error
	stop context.CancelFunc // detiene el servidor antes de que termine la prueba
}

func (s *server) transfers() []Transfer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Transfer(nil), s.xfer...)
}

func (s *server) waitTransfers(t *testing.T, n int) []Transfer {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if x := s.transfers(); len(x) >= n {
			return x
		}
	}
	t.Fatalf("transferencias = %+v", s.transfers())
	return nil
}

func start(t *testing.T, proto string, files ...string) *server {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &server{done: make(chan error, 1)}
	ready := make(chan string, 1)
	go func() {
		s.done <- Serve(ctx, Config{Addr: "127.0.0.1:0", Proto: proto, Files: files,
			OnListening: func(a string) { ready <- a },
			OnTransfer:  func(x Transfer) { s.mu.Lock(); s.xfer = append(s.xfer, x); s.mu.Unlock() }})
	}()
	select {
	case s.addr = <-ready:
	case err := <-s.done:
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := <-s.done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return s
}

func image(t *testing.T, name string, size int) (string, []byte) {
	t.Helper()
	b := make([]byte, size)
	rand.Read(b)
	p := filepath.Join(t.TempDir(), name)
	os.WriteFile(p, b, 0o600)
	return p, b
}

func TestValidate(t *testing.T) {
	for _, c := range []Config{
		{Addr: "0.0.0.0:6969", Proto: "tftp"},
		{Addr: ":6969", Proto: "tftp"},
		{Addr: "127.0.0.1:69", Proto: "tftp"},
		{Addr: "127.0.0.1:8080", Proto: "ftp"},
		{Addr: "127.0.0.1:8080", Proto: "http"}, // sin archivos
	} {
		if err := Serve(context.Background(), c); err == nil {
			t.Errorf("%+v aceptado", c)
		}
	}
	d := t.TempDir()
	a, _ := image(t, "c3560.bin", 1)
	b := filepath.Join(d, "c3560.bin")
	os.WriteFile(b, nil, 0o600)
	if _, err := Publish([]string{a, b}); err == nil {
		t.Error("dos archivos con el mismo nombre publicados")
	}
	if _, err := Publish([]string{d}); err == nil {
		t.Error("carpeta publicada")
	}
	if _, err := Publish([]string{"rel.bin"}); err == nil {
		t.Error("ruta relativa publicada")
	}
}

// ---- cliente TFTP mínimo para las pruebas ----

type tftpClient struct {
	t    *testing.T
	conn *net.UDPConn
	srv  *net.UDPAddr
}

func dialTFTP(t *testing.T, addr string) *tftpClient {
	t.Helper()
	srv, _ := net.ResolveUDPAddr("udp", addr)
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &tftpClient{t: t, conn: c, srv: srv}
}

func (c *tftpClient) send(to *net.UDPAddr, b []byte) { c.conn.WriteToUDP(b, to) }

func (c *tftpClient) recv() ([]byte, *net.UDPAddr) {
	c.t.Helper()
	buf := make([]byte, 70000)
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		c.t.Fatal(err)
	}
	return buf[:n], from
}

func rrq(file string, opts ...string) []byte {
	b := []byte{0, 1}
	for _, s := range append([]string{file, "octet"}, opts...) {
		b = append(append(b, s...), 0)
	}
	return b
}

func ack(n uint16) []byte { return []byte{0, 4, byte(n >> 8), byte(n)} }

// get descarga un archivo; con opciones espera OACK y lo confirma.
func (c *tftpClient) get(file string, blk int, opts ...string) ([]byte, map[string]string) {
	c.t.Helper()
	c.send(c.srv, rrq(file, opts...))
	var out bytes.Buffer
	oack := map[string]string{}
	var tid *net.UDPAddr
	for want := uint16(1); ; want++ {
		p, from := c.recv()
		if tid == nil {
			tid = from
		}
		op := binary.BigEndian.Uint16(p)
		if op == 6 {
			f := strings.Split(strings.TrimSuffix(string(p[2:]), "\x00"), "\x00")
			for i := 0; i+1 < len(f); i += 2 {
				oack[f[i]] = f[i+1]
			}
			c.send(tid, ack(0))
			want--
			continue
		}
		if op == 5 {
			c.t.Fatalf("error TFTP %d: %s", binary.BigEndian.Uint16(p[2:]), p[4:])
		}
		if op != 3 || binary.BigEndian.Uint16(p[2:]) != want {
			c.t.Fatalf("paquete inesperado op=%d bloque=%d (esperaba %d)", op, binary.BigEndian.Uint16(p[2:]), want)
		}
		out.Write(p[4:])
		c.send(tid, ack(want))
		if len(p)-4 < blk {
			return out.Bytes(), oack
		}
	}
}

func (c *tftpClient) expectError(code uint16) {
	c.t.Helper()
	p, _ := c.recv()
	if binary.BigEndian.Uint16(p) != 5 || binary.BigEndian.Uint16(p[2:]) != code {
		c.t.Fatalf("esperaba error %d, llegó %q", code, p)
	}
}

func TestTFTPReadPlain(t *testing.T) {
	p, want := image(t, "c2960-lanbase.bin", 512*3) // múltiplo exacto: termina con bloque vacío
	s := start(t, "tftp", p)
	got, _ := dialTFTP(t, s.addr).get("c2960-lanbase.bin", 512)
	if !bytes.Equal(got, want) {
		t.Fatalf("contenido distinto: %d vs %d bytes", len(got), len(want))
	}
	x := s.waitTransfers(t, 1)[0]
	if x.Proto != "tftp" || x.File != "c2960-lanbase.bin" || x.Bytes != int64(len(want)) || x.Result != "ok" || !strings.HasPrefix(x.Client, "127.0.0.1:") {
		t.Fatalf("transferencia = %+v", x)
	}
}

func TestTFTPOptions(t *testing.T) {
	p, want := image(t, "cat9k.bin", 20000)
	s := start(t, "tftp", p)
	got, oack := dialTFTP(t, s.addr).get("/cat9k.bin", 1428, "blksize", "1428", "tsize", "0", "timeout", "3", "windowsize", "8")
	if !bytes.Equal(got, want) {
		t.Fatal("contenido distinto con blksize")
	}
	if oack["blksize"] != "1428" || oack["tsize"] != "20000" || oack["timeout"] != "3" || oack["windowsize"] != "" {
		t.Fatalf("oack = %v", oack)
	}
	// blksize fuera de rango se acota al máximo permitido.
	_, oack = dialTFTP(t, s.addr).get("cat9k.bin", 65464, "BLKSIZE", "99999")
	if oack["blksize"] != "65464" {
		t.Fatalf("oack = %v", oack)
	}
}

func TestTFTPRejects(t *testing.T) {
	p, _ := image(t, "ok.bin", 10)
	secret := filepath.Join(filepath.Dir(p), "secreto.txt")
	os.WriteFile(secret, []byte("x"), 0o600)
	s := start(t, "tftp", p)
	c := dialTFTP(t, s.addr)
	for _, name := range []string{"secreto.txt", "../" + filepath.Base(filepath.Dir(p)) + "/secreto.txt", secret, "", "."} {
		c.send(c.srv, rrq(name))
		c.expectError(1)
	}
	wrq := rrq("ok.bin")
	wrq[1] = 2
	c.send(c.srv, wrq)
	c.expectError(2)
	// Basura y paquetes truncados no tumban el servidor.
	for _, junk := range [][]byte{{}, {0}, {0, 1}, {0, 1, 'a'}, {0, 9, 0, 0}, bytes.Repeat([]byte{0xff}, 600)} {
		c.send(c.srv, junk)
	}
	got, _ := c.get("ok.bin", 512)
	if len(got) != 10 {
		t.Fatal("el servidor dejó de responder tras basura")
	}
	failed := 0
	for _, x := range s.transfers() {
		if x.Result != "ok" {
			failed++
			if !x.Rejected {
				t.Errorf("rechazo sin marcar: %+v", x)
			}
		}
	}
	if failed < 6 {
		t.Fatalf("rechazos no registrados: %+v", s.transfers())
	}
}

func TestTFTPRetransmitsAndIgnoresStrangers(t *testing.T) {
	p, want := image(t, "x.bin", 700)
	s := start(t, "tftp", p)
	c := dialTFTP(t, s.addr)
	c.send(c.srv, rrq("x.bin", "timeout", "1"))
	p1, tid := c.recv() // OACK
	if binary.BigEndian.Uint16(p1) != 6 {
		t.Fatalf("esperaba OACK: %q", p1)
	}
	again, _ := c.recv() // sin ACK: lo repite
	if !bytes.Equal(again, p1) {
		t.Fatal("no retransmitió el OACK")
	}
	// Un intruso con otro puerto recibe error 5 y la transferencia sigue.
	intruder := dialTFTP(t, s.addr)
	intruder.send(tid, ack(0))
	intruder.expectError(5)
	c.send(tid, ack(0))
	d1, _ := c.recv()
	c.send(tid, ack(1))
	c.send(tid, ack(1)) // ACK duplicado: no debe provocar envío doble (Sorcerer's Apprentice)
	d2, _ := c.recv()
	if binary.BigEndian.Uint16(d2[2:]) != 2 {
		t.Fatalf("bloque %d", binary.BigEndian.Uint16(d2[2:]))
	}
	c.send(tid, ack(2))
	if got := append(d1[4:], d2[4:]...); !bytes.Equal(got, want) {
		t.Fatal("contenido distinto")
	}
	c.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, _, err := c.conn.ReadFromUDP(make([]byte, 600)); err == nil {
		t.Fatalf("paquete de más tras el ACK duplicado (%d bytes)", n)
	}
	if x := s.waitTransfers(t, 1)[0]; x.Result != "ok" || x.Bytes != 700 {
		t.Fatalf("%+v", x)
	}
}

func TestTFTPBlockRollover(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	p, want := image(t, "grande.bin", 8*65540)
	s := start(t, "tftp", p)
	got, _ := dialTFTP(t, s.addr).getRollover("grande.bin", 8)
	if !bytes.Equal(got, want) {
		t.Fatalf("contenido distinto tras dar la vuelta el número de bloque: %d vs %d", len(got), len(want))
	}
}

// getRollover acepta que el bloque pase de 65535 a 0.
func (c *tftpClient) getRollover(file string, blk int) ([]byte, map[string]string) {
	c.send(c.srv, rrq(file, "blksize", strconv.Itoa(blk)))
	p, tid := c.recv()
	if binary.BigEndian.Uint16(p) != 6 {
		c.t.Fatalf("%q", p)
	}
	c.send(tid, ack(0))
	var out bytes.Buffer
	for want := uint16(1); ; want++ {
		p, _ := c.recv()
		if binary.BigEndian.Uint16(p) != 3 || binary.BigEndian.Uint16(p[2:]) != want {
			c.t.Fatalf("bloque %d, esperaba %d", binary.BigEndian.Uint16(p[2:]), want)
		}
		out.Write(p[4:])
		c.send(tid, ack(want))
		if len(p)-4 < blk {
			return out.Bytes(), nil
		}
	}
}

func TestHTTPServesOnlyPublishedWithRange(t *testing.T) {
	p, want := image(t, "isr4400.bin", 5000)
	os.WriteFile(filepath.Join(filepath.Dir(p), "otro.txt"), []byte("no"), 0o600)
	s := start(t, "http", p)
	base := "http://" + s.addr + "/"
	r, err := http.Get(base + "isr4400.bin")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 200 || !bytes.Equal(got, want) {
		t.Fatalf("%d, %d bytes", r.StatusCode, len(got))
	}
	req, _ := http.NewRequest("GET", base+"isr4400.bin", nil)
	req.Header.Set("Range", "bytes=100-199")
	r, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = io.ReadAll(r.Body)
	r.Body.Close()
	if r.StatusCode != 206 || !bytes.Equal(got, want[100:200]) {
		t.Fatalf("range: %d %d bytes", r.StatusCode, len(got))
	}
	for _, path := range []string{"", "otro.txt", "../otro.txt", "%2e%2e/otro.txt", "isr4400.bin/", p} {
		r, err := http.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 404 || bytes.Contains(b, []byte("isr4400")) {
			t.Errorf("%q: %d %q", path, r.StatusCode, b)
		}
	}
	r, _ = http.Post(base+"isr4400.bin", "application/octet-stream", strings.NewReader("x"))
	if r.StatusCode != 405 {
		t.Errorf("POST: %d", r.StatusCode)
	}
	r.Body.Close()
	x := s.waitTransfers(t, 2)
	if x[0].File != "isr4400.bin" || x[0].Bytes != 5000 || x[0].Result != "ok" || x[1].Bytes != 100 {
		t.Fatalf("%+v", x[:2])
	}
	for _, r := range s.waitTransfers(t, 9)[2:] {
		if !r.Rejected || r.Result != "error" {
			t.Errorf("404/405 sin marcar como rechazo: %+v", r)
		}
	}
}

func TestRedirectHint(t *testing.T) {
	h := TFTPRedirectHint("10.0.0.5", 6969)
	if !strings.Contains(h, "udp dport 69 redirect to :6969") {
		t.Fatal(h)
	}
	tf := Hint("tftp", "10.0.0.5:6969", []string{"/x/a.bin"})
	if !strings.Contains(tf, "copy tftp://10.0.0.5/a.bin flash:") || !strings.Contains(tf, "redirect to :6969") {
		t.Fatal(tf)
	}
	ht := Hint("http", "10.0.0.5:8080", []string{"/x/a.bin", "/y/b.cfg"})
	if !strings.Contains(ht, "copy http://10.0.0.5:8080/a.bin flash:") || !strings.Contains(ht, "http://10.0.0.5:8080/b.cfg") || strings.Contains(ht, "nft") {
		t.Fatal(ht)
	}
	if h := Hint("http", "0.0.0.0:8080", []string{"/x/a.bin"}); !strings.Contains(h, "http://IP-DE-ESTA-MÁQUINA:8080/a.bin") {
		t.Fatal(h)
	}
	_ = fmt.Sprint
}

// La regla de nftables es estrecha (solo la IP de escucha), vive en una tabla propia de ese
// servidor y trae el comando exacto para quitarla.
func TestRedirectHintIsNarrow(t *testing.T) {
	h := RedirectHint("tftp", "10.0.0.5", 6969)
	for _, w := range []string{"nft add table ip macuahuitl_tftp_6969", "ip daddr 10.0.0.5 udp dport 69 redirect to :6969"} {
		if !strings.Contains(h, w) {
			t.Errorf("falta %q en %s", w, h)
		}
	}
	if strings.Contains(h, "table ip macuahuitl;") || strings.Contains(h, "pre udp dport") {
		t.Errorf("sigue la regla ancha: %s", h)
	}
	if got, want := RedirectCleanup("tftp", "10.0.0.5", 6969), "sudo nft delete table ip macuahuitl_tftp_6969"; got != want {
		t.Errorf("cleanup = %q", got)
	}
	if h := RedirectHint("ftp", "fd00::5", 2121); !strings.Contains(h, "table ip6 macuahuitl_ftp_2121") || !strings.Contains(h, "ip6 daddr fd00::5 tcp dport 21") {
		t.Errorf("IPv6: %s", h)
	}
	if RedirectCleanup("http", "10.0.0.5", 8080) != "" {
		t.Error("http no tiene regla que quitar")
	}
	// Con 0.0.0.0 no hay IP que fijar: se pide la de la máquina, no se deja la regla ancha.
	if h := RedirectHint("scp", "0.0.0.0", 2222); !strings.Contains(h, "ip daddr IP-DE-ESTA-MÁQUINA tcp dport 22") {
		t.Errorf("0.0.0.0: %s", h)
	}
	if hh := ServerHint(Config{Proto: "scp"}, Ready{Addr: "10.0.0.5:2222"}, nil); !strings.Contains(hh, "sudo nft delete table ip macuahuitl_scp_2222") {
		t.Errorf("la pista no trae cómo quitar la regla:\n%s", hh)
	}
}

// FTP manda la credencial en claro: la pista lo dice y sugiere borrarla del equipo al terminar.
func TestFTPHintWarnsCleartext(t *testing.T) {
	h := ServerHint(Config{Proto: "ftp"}, Ready{Addr: "10.0.0.5:2121", User: "mac", Pass: "pw"}, []string{"a.bin"})
	for _, w := range []string{"en claro", "no ip ftp password"} {
		if !strings.Contains(h, w) {
			t.Errorf("falta %q en\n%s", w, h)
		}
	}
}

// El rango de datos pasivos no baja de 1024.
func TestFTPPassiveRangeMin(t *testing.T) {
	dir := t.TempDir()
	for _, r := range [][2]uint16{{80, 90}, {1023, 1100}, {0, 5000}, {2000, 1500}} {
		if err := Check(Config{Addr: "127.0.0.1:2121", Proto: "ftp", FromDir: dir, PassivePorts: r}); err == nil {
			t.Errorf("rango %v aceptado", r)
		}
	}
	for _, r := range [][2]uint16{{0, 0}, {1024, 1030}, {50000, 50031}} {
		if err := Check(Config{Addr: "127.0.0.1:2121", Proto: "ftp", FromDir: dir, PassivePorts: r}); err != nil {
			t.Errorf("rango %v: %v", r, err)
		}
	}
}

// Revisión: un origen no verificado (RRQ falsificable) no puede retener cupos ni
// provocar muchos reenvíos; el timeout pedido solo vale tras el primer ACK.
func TestTFTPUnverifiedPeerIsCheap(t *testing.T) {
	p, _ := image(t, "x.bin", 100)
	s := start(t, "tftp", p)
	c := dialTFTP(t, s.addr)
	c.send(c.srv, rrq("x.bin", "timeout", "255"))
	got := 0
	deadline := time.Now().Add(7 * time.Second)
	for time.Now().Before(deadline) && len(s.transfers()) == 0 {
		c.conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		if _, _, err := c.conn.ReadFromUDP(make([]byte, 600)); err == nil {
			got++
		}
	}
	x := s.transfers()
	if len(x) != 1 || x[0].Result != "error" || x[0].Duration > 5*time.Second {
		t.Fatalf("la transferencia sin ACK no terminó pronto: %+v", x)
	}
	if got > 2 {
		t.Fatalf("%d paquetes a un origen sin verificar", got)
	}
}

func TestTFTPPerClientLimit(t *testing.T) {
	p, _ := image(t, "x.bin", 100)
	s := start(t, "tftp", p)
	for i := 0; i < 2; i++ {
		c := dialTFTP(t, s.addr)
		c.send(c.srv, rrq("x.bin"))
		c.recv() // DATA 1, sin ACK: el cupo queda ocupado
	}
	c := dialTFTP(t, s.addr)
	c.send(c.srv, rrq("x.bin"))
	c.expectError(0)
}
