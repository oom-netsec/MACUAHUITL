package transfer

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// scpPeer es un par SCP de prueba que recibe una subida. stalled: acepta el encabezado y deja de leer (no
// consume ni ajusta la ventana del canal); si no, consume despacio pero sin parar.
func scpPeer(t *testing.T, stalled bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
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
					if r.Type != "exec" {
						continue
					}
					ch.Write([]byte{0})
					br := bufio.NewReader(ch)
					hdr, _ := br.ReadString('\n') // C0644 size name
					var size int64
					fmt.Sscanf(hdr, "C0644 %d", &size)
					ch.Write([]byte{0})
					if stalled {
						time.Sleep(time.Minute) // sin leer: la ventana del canal se agota
						return
					}
					buf := make([]byte, 32<<10)
					for left := size + 1; left > 0; { // los datos y el \0 final
						time.Sleep(2 * time.Millisecond)
						k, err := br.Read(buf[:min(int64(len(buf)), left)])
						if err != nil {
							return
						}
						left -= int64(k)
					}
					ch.Write([]byte{0})
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func slowUpload(t *testing.T, stalled bool) (n *atomic.Int64, done chan error, cancel func()) {
	addr := scpPeer(t, stalled)
	pub := t.TempDir()
	os.WriteFile(filepath.Join(pub, "big.bin"), make([]byte, 12<<20), 0o600)
	n = new(atomic.Int64)
	req := Request{Net: rawNet, URL: &url.URL{Scheme: "scp", Host: addr, Path: "/big.bin"}, FromDir: pub, Name: "big.bin", Timeout: time.Minute}
	req.SSH = func(ctx context.Context) (SSHSession, error) {
		c, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "u", HostKeyCallback: ssh.InsecureIgnoreHostKey()})
		return actSession{clientSession{c}, n}, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done = make(chan error, 1)
	go func() { _, err := Upload(ctx, req); done <- err }()
	return n, done, cancel
}

// Un par que no lee ni ajusta la ventana: el crédito falso es lo que cabe en la ventana (una sola vez); después los
// Write se bloquean, el contador se detiene y el keepalive de la sesión cierra a los 3 fallos.
func TestKeepaliveSubidaConParQueNoLee(t *testing.T) {
	n, done, cancel := slowUpload(t, true)
	defer cancel()
	time.Sleep(1500 * time.Millisecond)
	a := n.Load()
	time.Sleep(500 * time.Millisecond)
	if b := n.Load(); b != a || a > 8<<20 {
		t.Fatalf("actividad con un par que no consume: %d -> %d", a, b)
	}
	select {
	case err := <-done:
		t.Fatalf("la subida no debía terminar: %v", err)
	default:
	}
}

// Un par lento que sí consume ajusta la ventana: la actividad sigue creciendo y la subida termina.
func TestKeepaliveSubidaConParLentoQueConsume(t *testing.T) {
	n, done, cancel := slowUpload(t, false)
	defer cancel()
	last, grew := int64(0), 0
	deadline := time.After(40 * time.Second)
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			if grew < 3 {
				t.Fatalf("la actividad creció solo %d veces", grew)
			}
			return
		case <-deadline:
			t.Fatal("la subida lenta no terminó")
		case <-time.After(100 * time.Millisecond):
			if v := n.Load(); v > last {
				grew++
				last = v
			}
		}
	}
}
