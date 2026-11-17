package fileserve

import (
	"bufio"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/pkg/sftp"
)

// Al detener el servidor HTTP con una descarga a medias, Serve no vuelve hasta que esa
// transferencia quedó registrada: el que llama cierra su canal de eventos justo después.
func TestHTTPServeEsperaAlHandlerAntesDeVolver(t *testing.T) {
	p, _ := image(t, "grande.bin", 32<<20)
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		var mu sync.Mutex
		var got []Transfer
		ready := make(chan string, 1)
		done := make(chan error, 1)
		go func() {
			done <- Serve(ctx, Config{Addr: "127.0.0.1:0", Proto: "http", Files: []string{p},
				OnListening: func(a string) { ready <- a },
				OnTransfer:  func(x Transfer) { mu.Lock(); got = append(got, x); mu.Unlock() }})
		}()
		addr := <-ready
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		c.(*net.TCPConn).SetReadBuffer(16 << 10)
		io.WriteString(c, "GET /grande.bin HTTP/1.1\r\nHost: x\r\n\r\n")
		if _, err := io.ReadFull(bufio.NewReader(c), make([]byte, 64<<10)); err != nil {
			t.Fatal(err)
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		x := append([]Transfer(nil), got...)
		mu.Unlock()
		c.Close()
		if len(x) != 1 || x[0].Result == "ok" {
			t.Fatalf("vuelta %d: Serve volvió con %+v, quiero 1 transferencia interrumpida", i, x)
		}
	}
}

// Leer más allá del final (lo hace `sftp get` de OpenSSH al encolar lecturas) no cuenta bytes:
// lo auditado es lo entregado, nunca el offset pedido.
func TestSFTPLecturaMasAllaDelFinal(t *testing.T) {
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "a.bin"), []byte("0123456789"), 0o600)
	s, r := startCfg(t, Config{Proto: "sftp", FromDir: pub})
	cl, err := sftp.NewClient(mustDial(t, s.addr, r))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	// Solo una lectura más allá del final: nada entregado, lectura incompleta.
	f, err := cl.Open("/a.bin")
	if err != nil {
		t.Fatal(err)
	}
	f.ReadAt(make([]byte, 32<<10), 1<<30)
	f.Close()
	// Lectura completa más una lectura más allá del final: ok con el tamaño real.
	f, err = cl.Open("/a.bin")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(f); string(b) != "0123456789" {
		t.Fatalf("lectura = %q", b)
	}
	f.ReadAt(make([]byte, 32<<10), 1<<30)
	f.Close()

	x := s.waitTransfers(t, 2)
	if x[0].Bytes != 0 || x[0].Result == "ok" {
		t.Errorf("solo más allá del final: bytes=%d result=%s, quiero 0 y error", x[0].Bytes, x[0].Result)
	}
	if x[1].Bytes != 10 || x[1].Result != "ok" {
		t.Errorf("completa: bytes=%d result=%s, quiero 10 y ok", x[1].Bytes, x[1].Result)
	}
}
