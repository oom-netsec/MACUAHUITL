package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Un servidor que acepta TCP y no contesta: cancelar el ctx a mitad del handshake corta OpenSSH sin dejar goroutines.
func TestOpenSSHCanceladoEnElHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { // acepta y calla; las conexiones se cierran al terminar la prueba
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	ap := netip.MustParseAddrPort(ln.Addr().String())
	g := NewGuard(nil, nil)
	if err := g.Allow(context.Background(), "j", []string{ap.Addr().String()}); err != nil {
		t.Fatal(err)
	}
	g.AllowAnyOnPorts("j", []uint16{ap.Port()})
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	_, err = OpenSSH(ctx, g, "j", ap.Addr().String(), ap.Port(), testCred("pw"), ssh.InsecureIgnoreHostKey(), SSHOptions{HandshakeTimeout: 30 * time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("tardó %v", d)
	}
	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before+1 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before+1 {
		t.Fatalf("goroutines: %d -> %d", before, n)
	}
	// Con el ctx ya cancelado ni se intenta la conexión.
	if _, err := OpenSSH(ctx, g, "j", ap.Addr().String(), ap.Port(), testCred("pw"), ssh.InsecureIgnoreHostKey(), SSHOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("ctx cancelado: err = %v", err)
	}
}

// Cancelar el ctx después del handshake no cierra la sesión abierta.
func TestOpenSSHCancelarDespuesNoCierra(t *testing.T) {
	g, host, port, hk := startSim(t)
	ctx, cancel := context.WithCancel(context.Background())
	s, err := OpenSSH(ctx, g, "j", host, port, testCred("pw"), ssh.FixedHostKey(hk), SSHOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cancel()
	time.Sleep(200 * time.Millisecond)
	sess, err := s.Client().NewSession()
	if err != nil {
		t.Fatalf("la sesión se cerró al cancelar el ctx: %v", err)
	}
	sess.Close()
	if _, _, err := s.Shell(); err != nil {
		t.Fatal(err)
	}
}
