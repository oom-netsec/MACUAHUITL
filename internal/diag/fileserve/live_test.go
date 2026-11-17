package fileserve

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

func TestLiveNilSafe(t *testing.T) {
	var l *Live
	l.add(5)
	l.atLeast(5)
	l.setTotal(5)
	if l.Bytes() != 0 || l.Total() != 0 {
		t.Fatal("un Live nil debe dar 0")
	}
}

func TestLiveConcurrent(t *testing.T) {
	l := &Live{}
	var wg sync.WaitGroup
	for i := 1; i <= 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); l.atLeast(int64(i * 10)) }()
		go func() { defer wg.Done(); l.atLeast(int64(i)) }()
	}
	wg.Wait()
	if l.Bytes() != 500 {
		t.Fatalf("atLeast = %d, quería el máximo 500", l.Bytes())
	}
	m := &Live{}
	for range 40 {
		wg.Add(1)
		go func() { defer wg.Done(); m.add(3) }()
	}
	wg.Wait()
	m.setTotal(9)
	if m.Bytes() != 120 || m.Total() != 9 {
		t.Fatalf("add/total = %d/%d", m.Bytes(), m.Total())
	}
}

// ---- contador por protocolo ----

type liveRec struct {
	mu     sync.Mutex
	ev     []string
	starts []*Live
	ends   []Transfer
}

func (r *liveRec) onStart(l *Live) {
	r.mu.Lock()
	r.ev, r.starts = append(r.ev, "start"), append(r.starts, l)
	r.mu.Unlock()
}

func (r *liveRec) onTransfer(x Transfer) {
	r.mu.Lock()
	r.ev, r.ends = append(r.ev, "end"), append(r.ends, x)
	r.mu.Unlock()
}

func (r *liveRec) snap() (starts []*Live, ends []Transfer, ev []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*Live(nil), r.starts...), append([]Transfer(nil), r.ends...), append([]string(nil), r.ev...)
}

func (r *liveRec) waitEnds(t *testing.T, n int) []Transfer {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if _, e, _ := r.snap(); len(e) >= n {
			return e
		}
	}
	_, e, ev := r.snap()
	t.Fatalf("transferencias = %+v eventos = %v", e, ev)
	return nil
}

// one espera una transferencia con sesión: OnStart una vez y antes de OnTransfer, el mismo
// puntero en t.Live y Bytes() == t.Bytes al final.
func (r *liveRec) one(t *testing.T) (*Live, Transfer) {
	t.Helper()
	x := r.waitEnds(t, 1)[0]
	starts, _, ev := r.snap()
	if len(starts) != 1 || len(ev) != 2 || ev[0] != "start" || ev[1] != "end" {
		t.Fatalf("eventos = %v", ev)
	}
	if x.Live == nil || x.Live != starts[0] {
		t.Fatalf("t.Live = %p, OnStart dio %p", x.Live, starts[0])
	}
	if x.Live.Bytes() != x.Bytes {
		t.Fatalf("Live.Bytes = %d, Transfer.Bytes = %d", x.Live.Bytes(), x.Bytes)
	}
	if x.Live.Proto != x.Proto || x.Live.Client != x.Client || x.Live.File != x.File {
		t.Fatalf("Live %+v distinto de %+v", x.Live, x)
	}
	return x.Live, x
}

func liveStart(t *testing.T, c Config) (*liveRec, Ready) {
	t.Helper()
	rec := &liveRec{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan Ready, 1)
	c.Addr = "127.0.0.1:0"
	if c.Proto == "tftp" && c.Write && len(c.Allow) == 0 {
		c.Allow = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	c.OnReady = func(r Ready) { ready <- r }
	c.OnStart, c.OnTransfer = rec.onStart, rec.onTransfer
	go func() { done <- Serve(ctx, c) }()
	var r Ready
	select {
	case r = <-ready:
	case err := <-done:
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); <-done })
	return rec, r
}

func TestLiveTFTPRead(t *testing.T) {
	p, want := image(t, "img.bin", 512*3+7)
	for _, opts := range [][]string{nil, {"tsize", "0"}, {"blksize", "1024"}} {
		rec, r := liveStart(t, Config{Proto: "tftp", Files: []string{p}})
		blk := 512
		if len(opts) == 2 && opts[0] == "blksize" {
			blk = 1024
		}
		got, _ := dialTFTP(t, r.Addr).get("img.bin", blk, opts...)
		if !bytes.Equal(got, want) {
			t.Fatalf("%v: contenido distinto", opts)
		}
		l, x := rec.one(t)
		if l.Total() != int64(len(want)) || x.Bytes != int64(len(want)) {
			t.Fatalf("%v: total=%d bytes=%d", opts, l.Total(), x.Bytes)
		}
	}
}

func TestLiveTFTPReadHalfway(t *testing.T) {
	p, _ := image(t, "img.bin", 512*5)
	rec, r := liveStart(t, Config{Proto: "tftp", Files: []string{p}})
	c := dialTFTP(t, r.Addr)
	c.send(c.srv, rrq("img.bin"))
	b1, tid := c.recv()
	if len(b1) != 4+512 {
		t.Fatalf("bloque 1 de %d", len(b1))
	}
	c.send(tid, ack(1))
	b2, _ := c.recv() // el bloque 2 sale después de contar el 1; su ACK no se manda
	if binary.BigEndian.Uint16(b2[2:]) != 2 {
		t.Fatalf("esperaba el bloque 2: %v", b2[:4])
	}
	starts, ends, _ := rec.snap()
	if len(starts) != 1 || len(ends) != 0 {
		t.Fatalf("starts=%d ends=%d", len(starts), len(ends))
	}
	if starts[0].Bytes() != 512 || starts[0].Total() != 512*5 {
		t.Fatalf("a medias: %d/%d", starts[0].Bytes(), starts[0].Total())
	}
}

func TestLiveTFTPUnverifiedPeerHasNoSession(t *testing.T) {
	p, _ := image(t, "img.bin", 512*2)
	rec, r := liveStart(t, Config{Proto: "tftp", Files: []string{p}})
	c := dialTFTP(t, r.Addr)
	c.send(c.srv, rrq("img.bin")) // el par nunca responde
	x := rec.waitEnds(t, 1)[0]
	if starts, _, _ := rec.snap(); len(starts) != 0 || x.Live != nil || x.Result != "error" || x.Rejected {
		t.Fatalf("starts=%d transferencia=%+v", len(starts), x)
	}
}

func TestLiveTFTPWrite(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 512*3+9)
	for _, tc := range []struct {
		opts  []string
		total int64
	}{{nil, 0}, {[]string{"tsize", strconv.Itoa(len(data))}, int64(len(data))}} {
		rec, r := liveStart(t, Config{Proto: "tftp", Write: true, RecvDir: t.TempDir()})
		if code := dialTFTP(t, r.Addr).put("cfg", data, 512, tc.opts...); code != 0 {
			t.Fatalf("error %d", code)
		}
		l, x := rec.one(t)
		if l.Total() != tc.total || x.Bytes != int64(len(data)) {
			t.Fatalf("%v: total=%d bytes=%d", tc.opts, l.Total(), x.Bytes)
		}
	}
}

func TestLiveFTP(t *testing.T) {
	pub := t.TempDir()
	body := bytes.Repeat([]byte("a"), 3000)
	os.WriteFile(filepath.Join(pub, "a.bin"), body, 0o600)
	rec, r := liveStart(t, Config{Proto: "ftp", FromDir: pub, Write: true, RecvDir: t.TempDir()})
	f := ftpDial(t, r.Addr)
	f.login(r)
	dc := f.pasv()
	f.cmd(150, "RETR a.bin")
	io.ReadAll(dc)
	f.expect(226)
	l, x := rec.one(t)
	if l.Total() != 3000 || x.Bytes != 3000 || x.Dir != "lectura" {
		t.Fatalf("RETR total=%d bytes=%d", l.Total(), x.Bytes)
	}
	rec2, r2 := liveStart(t, Config{Proto: "ftp", FromDir: pub, Write: true, RecvDir: t.TempDir()})
	f = ftpDial(t, r2.Addr)
	f.login(r2)
	dc = f.pasv()
	f.cmd(150, "STOR run")
	dc.Write(body)
	dc.Close()
	f.expect(226)
	l, x = rec2.one(t)
	if l.Total() != 0 || x.Bytes != 3000 || x.Dir != "escritura" {
		t.Fatalf("STOR total=%d bytes=%d", l.Total(), x.Bytes)
	}
}

func TestLiveSCP(t *testing.T) {
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "img.bin"), bytes.Repeat([]byte("i"), 5000), 0o600)
	rec, r := liveStart(t, Config{Proto: "scp", FromDir: pub, Write: true, RecvDir: t.TempDir()})
	c := mustDial(t, r.Addr, r)
	if _, err := scpDownload(c, "img.bin"); err != nil {
		t.Fatal(err)
	}
	l, x := rec.one(t)
	if l.Total() != 5000 || x.Bytes != 5000 || x.Dir != "lectura" {
		t.Fatalf("fuente total=%d bytes=%d", l.Total(), x.Bytes)
	}
	rec2, r2 := liveStart(t, Config{Proto: "scp", Write: true, RecvDir: t.TempDir()})
	if err := scpUpload(mustDial(t, r2.Addr, r2), "cfg", "cfg", make([]byte, 4321)); err != nil {
		t.Fatal(err)
	}
	l, x = rec2.one(t)
	if l.Total() != 4321 || x.Bytes != 4321 {
		t.Fatalf("destino total=%d bytes=%d", l.Total(), x.Bytes)
	}
}

func TestLiveSFTP(t *testing.T) {
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "a.bin"), bytes.Repeat([]byte("a"), 70000), 0o600)
	rec, r := liveStart(t, Config{Proto: "sftp", FromDir: pub, Write: true, RecvDir: t.TempDir()})
	cl, err := sftp.NewClient(mustDial(t, r.Addr, r))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	f, err := cl.Open("/a.bin")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(f)
	f.Close()
	l, x := rec.one(t)
	if l.Total() != 70000 || x.Bytes != 70000 {
		t.Fatalf("lectura total=%d bytes=%d", l.Total(), x.Bytes)
	}
	rec2, r2 := liveStart(t, Config{Proto: "sftp", Write: true, RecvDir: t.TempDir()})
	cl2, err := sftp.NewClient(mustDial(t, r2.Addr, r2))
	if err != nil {
		t.Fatal(err)
	}
	defer cl2.Close()
	w, err := cl2.Create("/up")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(make([]byte, 40000))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	l, x = rec2.one(t)
	if l.Total() != 0 || x.Bytes != 40000 {
		t.Fatalf("escritura total=%d bytes=%d", l.Total(), x.Bytes)
	}
}

func TestLiveHTTP(t *testing.T) {
	p, want := image(t, "img.bin", 10000)
	for _, rng := range []string{"", "bytes=100-299"} {
		rec, r := liveStart(t, Config{Proto: "http", Files: []string{p}})
		req, _ := http.NewRequest("GET", "http://"+r.Addr+"/img.bin", nil)
		total := int64(len(want))
		if rng != "" {
			req.Header.Set("Range", rng)
			total = 200
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		l, x := rec.one(t)
		if l.Total() != total || x.Bytes != total {
			t.Fatalf("Range %q: total=%d bytes=%d", rng, l.Total(), x.Bytes)
		}
	}
}

func TestLiveHTTPHalfway(t *testing.T) {
	const size = 64 << 20
	p := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(size) // disperso: no ocupa disco
	f.Close()
	rec, r := liveStart(t, Config{Proto: "http", Files: []string{p}})
	resp, err := http.Get("http://" + r.Addr + "/big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.CopyN(io.Discard, resp.Body, 1<<20); err != nil {
		t.Fatal(err)
	}
	starts, ends, _ := rec.snap()
	if len(starts) != 1 || len(ends) != 0 {
		t.Fatalf("starts=%d ends=%d", len(starts), len(ends))
	}
	if b := starts[0].Bytes(); b <= 0 || b >= size || starts[0].Total() != size {
		t.Fatalf("a medias: %d/%d", b, starts[0].Total())
	}
	resp.Body.Close() // el servidor ve la conexión rota y la transferencia termina con error
	x := rec.waitEnds(t, 1)[0]
	if x.Live != starts[0] || x.Live.Bytes() != x.Bytes || x.Result != "error" {
		t.Fatalf("transferencia = %+v", x)
	}
}

// ---- rechazos: sin sesión y con su causa ----

func TestLiveRejectionsHaveCauseAndNoSession(t *testing.T) {
	p, _ := image(t, "img.bin", 100)
	cause := func(rec *liveRec) Transfer {
		t.Helper()
		x := rec.waitEnds(t, 1)[0]
		if starts, _, _ := rec.snap(); len(starts) != 0 || x.Live != nil || !x.Rejected {
			t.Fatalf("un rechazo no debe tener sesión: starts=%d %+v", len(starts), x)
		}
		return x
	}
	check := func(x Transfer, want string) {
		t.Helper()
		if x.Cause != want {
			t.Errorf("%s %q: causa %q, quería %q", x.Proto, x.Error, x.Cause, want)
		}
	}
	// TFTP en loopback.
	rec, r := liveStart(t, Config{Proto: "tftp", Files: []string{p}})
	c := dialTFTP(t, r.Addr)
	c.send(c.srv, rrq("nada"))
	c.expectError(1)
	check(cause(rec), "not_found")
	rec, r = liveStart(t, Config{Proto: "tftp", Files: []string{p}, Allow: []netip.Addr{netip.MustParseAddr("10.9.9.9")}})
	c = dialTFTP(t, r.Addr)
	c.send(c.srv, rrq("img.bin"))
	check(cause(rec), "origin_denied")
	rec, r = liveStart(t, Config{Proto: "tftp", Files: []string{p}})
	c = dialTFTP(t, r.Addr)
	c.send(c.srv, wrq("x"))
	c.expectError(2)
	check(cause(rec), "write_disabled")
	// HTTP.
	rec, r = liveStart(t, Config{Proto: "http", Files: []string{p}})
	http.Get("http://" + r.Addr + "/nada")
	check(cause(rec), "not_found")
	rec, r = liveStart(t, Config{Proto: "http", Files: []string{p}})
	http.Post("http://"+r.Addr+"/img.bin", "text/plain", nil)
	check(cause(rec), "method")
	rec, r = liveStart(t, Config{Proto: "http", Files: []string{p}, Allow: []netip.Addr{netip.MustParseAddr("10.9.9.9")}})
	http.Get("http://" + r.Addr + "/img.bin")
	check(cause(rec), "origin_denied")
	// FTP.
	rec, r = liveStart(t, Config{Proto: "ftp", Write: true, RecvDir: t.TempDir()})
	f := ftpDial(t, r.Addr)
	f.login(r)
	f.pasv()
	f.cmd(550, "RETR img.bin")
	check(cause(rec), "read_disabled")
	rec, r = liveStart(t, Config{Proto: "ftp", Files: []string{p}})
	f = ftpDial(t, r.Addr)
	f.login(r)
	f.pasv()
	f.cmd(550, "RETR nada")
	check(cause(rec), "not_found")
	rec, r = liveStart(t, Config{Proto: "ftp", Files: []string{p}})
	f = ftpDial(t, r.Addr)
	f.login(r)
	f.pasv()
	f.cmd(550, "STOR x")
	check(cause(rec), "write_disabled")
	rec, r = liveStart(t, Config{Proto: "ftp", Files: []string{p}, Allow: []netip.Addr{netip.MustParseAddr("10.9.9.9")}})
	if cn, err := net.Dial("tcp", r.Addr); err == nil {
		cn.Close()
	}
	check(cause(rec), "origin_denied")
	// SCP y SFTP.
	rec, r = liveStart(t, Config{Proto: "scp", Files: []string{p}})
	scpDownload(mustDial(t, r.Addr, r), "nada")
	check(cause(rec), "not_found")
	rec, r = liveStart(t, Config{Proto: "scp", Files: []string{p}})
	scpUpload(mustDial(t, r.Addr, r), "x", "x", []byte("1"))
	check(cause(rec), "write_disabled")
	rec, r = liveStart(t, Config{Proto: "scp", Write: true, RecvDir: t.TempDir()})
	scpDownload(mustDial(t, r.Addr, r), "x")
	check(cause(rec), "read_disabled")
	rec, r = liveStart(t, Config{Proto: "sftp", Files: []string{p}})
	cl, _ := sftp.NewClient(mustDial(t, r.Addr, r))
	cl.Open("/nada")
	check(cause(rec), "not_found")
	rec, r = liveStart(t, Config{Proto: "sftp", Files: []string{p}})
	cl, _ = sftp.NewClient(mustDial(t, r.Addr, r))
	cl.Create("/x")
	check(cause(rec), "write_disabled")
	rec, r = liveStart(t, Config{Proto: "sftp", Write: true, RecvDir: t.TempDir()})
	cl, _ = sftp.NewClient(mustDial(t, r.Addr, r))
	cl.Open("/x")
	check(cause(rec), "read_disabled")
}
