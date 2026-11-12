package fileserve

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// startCfg abre un servidor con la configuración dada (Addr y callbacks los pone aquí).
func startCfg(t *testing.T, c Config) (*server, Ready) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &server{done: make(chan error, 1), stop: cancel}
	ready := make(chan Ready, 1)
	c.Addr = "127.0.0.1:0"
	if c.Proto == "tftp" && c.Write && len(c.Allow) == 0 { // escribir por TFTP exige lista de IP
		c.Allow = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	c.OnReady = func(r Ready) { ready <- r }
	c.OnTransfer = func(x Transfer) { s.mu.Lock(); s.xfer = append(s.xfer, x); s.mu.Unlock() }
	go func() { s.done <- Serve(ctx, c) }()
	var r Ready
	select {
	case r = <-ready:
		s.addr = r.Addr
	case err := <-s.done:
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		if err := <-s.done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return s, r
}

func TestSafeName(t *testing.T) {
	ok := map[string]string{
		"running-config":        "running-config",
		"/cfg/r1.txt":           "r1.txt",
		"../../etc/passwd":      "passwd",
		`..\..\windows\win.ini`: "win.ini",
		"a/../b":                "b",
		"crashinfo_20260101":    "crashinfo_20260101",
	}
	for in, want := range ok {
		if got, err := SafeName(in); err != nil || got != want {
			t.Errorf("SafeName(%q) = %q, %v; quería %q", in, got, err, want)
		}
	}
	ok["ñandú-é.cfg"] = "ñandú-é.cfg"
	for _, in := range []string{"", ".", "..", "a/..", "a/", "x\x00y", "x\ny", "tab\there", "\x7f", strings.Repeat("a", 201),
		".bash_profile", ".hidden", "/cfg/.bashrc", ".ssh", // dotfiles: los lee el shell, el escritorio o el SSH
		" inicio", "fin ", "   ", " ", "\u00a0", "a\u202etxt.exe", "a\u200bb", "\ufeffx", "a\u00adb", // espacios en los extremos y Cf (RLO, ancho cero, BOM)
		"\xff\xfe", "ok\xc3", // UTF-8 inválido
	} {
		if got, err := SafeName(in); err == nil {
			t.Errorf("SafeName(%q) = %q, debió rechazarse", in, got)
		}
	}
}

// O_EXCL: ni un archivo ni un enlace simbólico con ese nombre se pisan.
func TestReceiverNeverOverwrites(t *testing.T) {
	dir := t.TempDir()
	r, err := newReceiver(dir, 100, 1000)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "viejo"), []byte("original"), 0o600)
	if _, err := r.create("viejo", 0); !errors.Is(err, errExists) {
		t.Fatalf("err = %v", err)
	}
	victim := filepath.Join(t.TempDir(), "victima")
	os.WriteFile(victim, []byte("intacto"), 0o600)
	os.Symlink(victim, filepath.Join(dir, "enlace"))
	if _, err := r.create("enlace", 0); err == nil {
		t.Fatal("siguió un enlace simbólico")
	}
	if b, _ := os.ReadFile(victim); string(b) != "intacto" {
		t.Fatalf("destino del enlace modificado: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "viejo")); string(b) != "original" {
		t.Fatalf("archivo existente modificado: %q", b)
	}
	f, err := r.create("nuevo", 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("hola"))
	sum, size, err := f.commit()
	want := sha256.Sum256([]byte("hola"))
	if err != nil || size != 4 || sum != hex.EncodeToString(want[:]) {
		t.Fatalf("commit = %s %d %v", sum, size, err)
	}
	if st, _ := os.Stat(f.path); st.Mode().Perm() != 0o600 {
		t.Fatalf("permisos %v", st.Mode())
	}
}

func TestReceiverCaps(t *testing.T) {
	dir := t.TempDir()
	r, _ := newReceiver(dir, 10, 15)
	if _, err := r.create("grande", 11); !errors.Is(err, errTooBig) {
		t.Fatalf("anunciado sobre el tope: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "grande")); err == nil {
		t.Fatal("se creó un archivo que no cabía")
	}
	f, _ := r.create("a", 0)
	if _, err := f.Write(make([]byte, 10)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{1}); !errors.Is(err, errTooBig) {
		t.Fatalf("tope por archivo: %v", err)
	}
	f.commit()
	g, _ := r.create("b", 0)
	if _, err := g.Write(make([]byte, 6)); !errors.Is(err, errTotal) { // 10 + 6 > 15
		t.Fatalf("tope total: %v", err)
	}
	g.abort()
	if _, err := os.Stat(filepath.Join(dir, "b")); err == nil {
		t.Fatal("abort dejó el archivo")
	}
	h, _ := r.create("c", 0) // abort devolvió el cupo: 5 bytes caben
	if _, err := h.Write(make([]byte, 5)); err != nil {
		t.Fatal(err)
	}
	h.commit()
}

// ---- TFTP: escritura ----

func wrq(file string, opts ...string) []byte {
	b := rrq(file, opts...)
	b[1] = 2
	return b
}

func dataPkt(n uint16, p []byte) []byte {
	return append(binary.BigEndian.AppendUint16([]byte{0, 3}, n), p...)
}

// put sube data con bloques de blk; devuelve el código de error TFTP (0 si terminó bien).
func (c *tftpClient) put(file string, data []byte, blk int, opts ...string) uint16 {
	c.t.Helper()
	c.send(c.srv, wrq(file, opts...))
	p, tid := c.recv()
	switch binary.BigEndian.Uint16(p) {
	case 5:
		return binary.BigEndian.Uint16(p[2:])
	case 4, 6:
	default:
		c.t.Fatalf("respuesta inesperada %v", p)
	}
	for n := uint16(1); ; n++ {
		lo := int(n-1) * blk
		hi := min(lo+blk, len(data))
		if lo > len(data) {
			lo, hi = len(data), len(data)
		}
		c.send(tid, dataPkt(n, data[lo:hi]))
		p, _ = c.recv()
		if binary.BigEndian.Uint16(p) == 5 {
			return binary.BigEndian.Uint16(p[2:])
		}
		if binary.BigEndian.Uint16(p) != 4 || binary.BigEndian.Uint16(p[2:]) != n {
			c.t.Fatalf("ACK inesperado %v", p)
		}
		if hi-lo < blk {
			return 0
		}
	}
}

func TestTFTPWrite(t *testing.T) {
	dir := t.TempDir()
	s, _ := startCfg(t, Config{Proto: "tftp", Write: true, RecvDir: dir})
	data := bytes.Repeat([]byte("hostname R1\n"), 200)
	if code := dialTFTP(t, s.addr).put("running-config", data, 512); code != 0 {
		t.Fatalf("error %d", code)
	}
	x := s.waitTransfers(t, 1)[0]
	sum := sha256.Sum256(data)
	if x.Result != "ok" || x.Dir != "escritura" || x.Bytes != int64(len(data)) || x.SHA256 != hex.EncodeToString(sum[:]) || x.Path != filepath.Join(dir, "running-config") {
		t.Fatalf("transferencia = %+v", x)
	}
	got, _ := os.ReadFile(x.Path)
	st, _ := os.Stat(x.Path)
	if !bytes.Equal(got, data) || st.Mode().Perm() != 0o600 {
		t.Fatalf("archivo guardado mal: %v", st.Mode())
	}
	// Con opciones, bloque exacto (cierra con bloque vacío) y nombre con ruta y "..".
	data2 := bytes.Repeat([]byte{7}, 1024*2)
	if code := dialTFTP(t, s.addr).put("../../r2/crashinfo", data2, 1024, "blksize", "1024", "tsize", "2048"); code != 0 {
		t.Fatalf("error %d", code)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "crashinfo")); err != nil || !bytes.Equal(b, data2) {
		t.Fatalf("crashinfo: %v", err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("archivos extra en la carpeta: %v", ents)
	}
	// Un archivo vacío también se recibe.
	if code := dialTFTP(t, s.addr).put("vacio", nil, 512); code != 0 {
		t.Fatalf("vacío: error %d", code)
	}
}

func TestTFTPWriteRefusals(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "existe"), []byte("original"), 0o600)
	s, _ := startCfg(t, Config{Proto: "tftp", Write: true, RecvDir: dir, MaxFile: 1000, MaxTotal: 1500})
	c := dialTFTP(t, s.addr)
	if code := c.put("existe", []byte("pisado"), 512); code != 6 {
		t.Fatalf("existente: código %d", code)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "existe")); string(b) != "original" {
		t.Fatalf("se pisó: %q", b)
	}
	for _, bad := range []string{"..", ".", "", "a/", "x\x01y"} {
		if code := c.put(bad, []byte("x"), 512); code != 2 {
			t.Errorf("%q: código %d", bad, code)
		}
	}
	// tsize anunciado sobre el tope: se rechaza sin crear nada.
	if code := c.put("grande", nil, 512, "tsize", "1001"); code != 3 {
		t.Fatalf("tsize grande: código %d", code)
	}
	// Sin tsize, el tope por archivo corta a media recepción y no deja un archivo a medias.
	if code := c.put("sorpresa", make([]byte, 1100), 512); code != 3 {
		t.Fatalf("exceso en vuelo: código %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "sorpresa")); err == nil {
		t.Fatal("quedó un archivo a medias")
	}
	// Tope total: 1000 + 600 > 1500.
	if code := c.put("uno", make([]byte, 1000), 512); code != 0 {
		t.Fatalf("uno: %d", code)
	}
	if code := c.put("dos", make([]byte, 600), 512); code != 3 {
		t.Fatalf("tope total: código %d", code)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 { // existe + uno
		t.Fatalf("carpeta: %v", ents)
	}
}

func TestTFTPReadAndWriteAreSeparate(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	// Solo lectura: WRQ rechazado con error TFTP.
	s := start(t, "tftp", p)
	c := dialTFTP(t, s.addr)
	c.send(c.srv, wrq("x"))
	c.expectError(2)
	// Solo escritura: RRQ rechazado aunque el nombre exista en otro lado.
	s2, _ := startCfg(t, Config{Proto: "tftp", Write: true, RecvDir: t.TempDir()})
	c2 := dialTFTP(t, s2.addr)
	c2.send(c2.srv, rrq("a.bin"))
	c2.expectError(2)
	// Lectura y escritura a la vez.
	s3, _ := startCfg(t, Config{Proto: "tftp", Files: []string{p}, Write: true, RecvDir: t.TempDir()})
	if got, _ := dialTFTP(t, s3.addr).get("a.bin", 512); len(got) != 10 {
		t.Fatal("lectura")
	}
	if code := dialTFTP(t, s3.addr).put("b", []byte("z"), 512); code != 0 {
		t.Fatalf("escritura: %d", code)
	}
}

func TestAllowList(t *testing.T) {
	p, _ := image(t, "a.bin", 10)
	dir := t.TempDir()
	// 127.0.0.1 no está permitida: el servidor no contesta ni escribe.
	s, _ := startCfg(t, Config{Proto: "tftp", Files: []string{p}, Write: true, RecvDir: dir, Allow: []netip.Addr{netip.MustParseAddr("10.9.9.9")}})
	c := dialTFTP(t, s.addr)
	c.send(c.srv, wrq("x"))
	c.send(c.srv, rrq("a.bin"))
	x := s.waitTransfers(t, 2)
	for _, e := range x {
		if !e.Rejected || e.Error != "origen no permitido" {
			t.Fatalf("%+v", e)
		}
	}
	c.conn.SetReadDeadline(timeIn(300))
	if n, _, err := c.conn.ReadFromUDP(make([]byte, 100)); err == nil {
		t.Fatalf("respondió a un origen no permitido (%d bytes)", n)
	}
	// Con la IP en la lista, sí.
	s2, _ := startCfg(t, Config{Proto: "tftp", Write: true, RecvDir: dir, Allow: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	if code := dialTFTP(t, s2.addr).put("ok", []byte("1"), 512); code != 0 {
		t.Fatalf("código %d", code)
	}
}

func TestServeWriteValidation(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]Config{
		"http escribe":          {Addr: "127.0.0.1:0", Proto: "http", Write: true, RecvDir: t.TempDir()},
		"nada que servir":       {Addr: "127.0.0.1:0", Proto: "tftp"},
		"todas sin lista":       {Addr: "0.0.0.0:6969", AllowAny: true, Proto: "tftp", Write: true, RecvDir: t.TempDir()},
		"carpeta relativa":      {Addr: "127.0.0.1:0", Proto: "tftp", Write: true, RecvDir: "rel"},
		"protocolo desconocido": {Addr: "127.0.0.1:0", Proto: "gopher", Write: true, RecvDir: t.TempDir()},
	} {
		if err := Serve(ctx, c); err == nil {
			t.Errorf("%s: debió fallar", name)
		}
	}
}

func timeIn(ms int) (t0 timeT) { return nowPlus(ms) }

var _ = net.IPv4

type timeT = time.Time

func nowPlus(ms int) time.Time { return time.Now().Add(time.Duration(ms) * time.Millisecond) }

// Escribir por TFTP exige --allow: en UDP el origen se falsifica, pero sin lista cualquiera escribiría.
func TestTFTPWriteRequiresAllow(t *testing.T) {
	c := Config{Addr: "127.0.0.1:6969", Proto: "tftp", Write: true, RecvDir: t.TempDir()}
	if err := Check(c); err == nil || !strings.Contains(err.Error(), "--allow") {
		t.Fatalf("TFTP con escritura y sin lista: %v", err)
	}
	c.Allow = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	if err := Check(c); err != nil {
		t.Fatalf("con lista: %v", err)
	}
	c.Allow, c.Write, c.Files = nil, false, nil
	c.FromDir = t.TempDir()
	if err := Check(c); err != nil {
		t.Fatalf("TFTP de solo lectura no pide lista: %v", err)
	}
}

// Los avisos de que la lista de IP no autentica en UDP viajan en la pista del equipo.
func TestTFTPWriteHintWarnsSpoofing(t *testing.T) {
	h := ServerHint(Config{Proto: "tftp", Write: true}, Ready{Addr: "10.0.0.1:6969"}, nil)
	if !strings.Contains(h, "falsific") {
		t.Fatalf("la pista no avisa que la IP de origen se falsifica en UDP:\n%s", h)
	}
}

// El tope de archivos devuelve el cupo al descartar y se comprueba en el mismo candado que el incremento.
func TestReceiverFileCountReleasedOnAbort(t *testing.T) {
	r, _ := newReceiver(t.TempDir(), 0, 0)
	r.maxFiles = 2
	a, _ := r.create("a", 0)
	if _, err := r.create("b", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := r.create("c", 0); !errors.Is(err, errTooMany) {
		t.Fatalf("tercero sobre el tope: %v", err)
	}
	a.abort()
	if _, err := r.create("c", 0); err != nil {
		t.Fatalf("abort no devolvió el cupo de archivos: %v", err)
	}
}

func TestReceiverFileCountConcurrent(t *testing.T) {
	r, _ := newReceiver(t.TempDir(), 0, 0)
	r.maxFiles = 5
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.create(fmt.Sprintf("f%d", i), 0); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 5 {
		t.Fatalf("se crearon %d archivos con tope 5", ok.Load())
	}
}
