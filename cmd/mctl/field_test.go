package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/serialcon"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func TestConsoleCommand(t *testing.T) {
	e := startCore(t)
	dev, port, err := serialcon.Pty()
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	in, keys := io.Pipe()
	out := &syncBuf{}
	done := make(chan error, 1)
	go func() { done <- run([]string{"--lang", "es", "console", port, "--baud", "115200"}, in, out) }()
	keys.Write([]byte("show clock\r"))
	buf := make([]byte, 64)
	n, _ := dev.Read(buf)
	if string(buf[:n]) != "show clock\r" {
		t.Fatalf("equipo recibió %q", buf[:n])
	}
	dev.Write([]byte("*10:00:00 UTC\r\nSwitch#"))
	for deadline := time.Now().Add(3 * time.Second); !strings.Contains(out.String(), "Switch#"); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("salida: %q", out.String())
		}
	}
	keys.Write([]byte("\x1db"))
	keys.Write([]byte("\x1dq"))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Ctrl-] q no cerró la consola")
	}
	if !strings.Contains(out.String(), "115200 8N1") || !strings.Contains(out.String(), "Ctrl-] q") {
		t.Fatalf("salida: %q", out.String())
	}
	logs, _ := filepath.Glob(filepath.Join(e.out, "console", "*.log"))
	if len(logs) != 1 {
		t.Fatalf("grabaciones: %v", logs)
	}
	rec, _ := os.ReadFile(logs[0])
	if !strings.Contains(string(rec), "Switch#") || !strings.Contains(string(rec), "### BREAK") {
		t.Fatalf("grabación:\n%s", rec)
	}
}

func TestServeAndHashCommands(t *testing.T) {
	startCore(t)
	dir := t.TempDir()
	img := filepath.Join(dir, "c9300.bin")
	os.WriteFile(img, []byte("abc"), 0o600)
	t.Chdir(dir)
	out, err := mctl(t, "", "serve", "http", "--addr", "127.0.0.1:0", "--file", "c9300.bin", "--for", "1")
	if err != nil || !strings.Contains(out, "sirviendo en 127.0.0.1:") || !strings.Contains(out, "/c9300.bin flash:") {
		t.Fatalf("serve: %q %v", out, err)
	}
	if _, err := mctl(t, "", "serve", "tftp", "--file", "c9300.bin"); err == nil {
		t.Fatal("serve sin --addr aceptado")
	}
	out, err = mctl(t, "", "hash", "c9300.bin", "--md5", "900150983cd24fb0d6963f7d28e17f72")
	if err != nil || !strings.Contains(out, "coincide") || !strings.Contains(out, "verify /md5 flash:c9300.bin") {
		t.Fatalf("hash: %q %v", out, err)
	}
	if out, err := mctl(t, "", "hash", "c9300.bin", "--md5", strings.Repeat("1", 32)); err == nil || !strings.Contains(out, "NO COINCIDE") {
		t.Fatalf("hash distinto: %q %v", out, err)
	}
}
