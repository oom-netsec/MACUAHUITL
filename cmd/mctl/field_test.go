package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

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
