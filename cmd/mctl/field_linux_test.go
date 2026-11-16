//go:build linux

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/serialcon"
)

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
