//go:build linux

package main

import (
	"strings"
	"testing"

	"io"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/serialcon"
)

func TestConsoleOutputIsRaw(t *testing.T) {
	startCore(t)
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm")
	dev, port, err := serialcon.Pty()
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()
	in, keys := io.Pipe()
	out := &syncBuf{}
	outIsTTY = func(io.Writer) bool { return true }
	defer func() { outIsTTY = func(io.Writer) bool { return false } }()
	done := make(chan error, 1)
	go func() { done <- run([]string{"--lang", "es", "console", port, "--baud", "115200"}, in, out) }()
	keys.Write([]byte("x"))
	buf := make([]byte, 8)
	dev.Read(buf)
	dev.Write([]byte("\x1b[2JSwitch#"))
	for deadline := time.Now().Add(3 * time.Second); !strings.Contains(out.String(), "Switch#"); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("salida: %q", out.String())
		}
	}
	keys.Write([]byte("\x1dq"))
	<-done
	if !strings.Contains(out.String(), "\x1b[2JSwitch#") {
		t.Fatalf("la consola no es cruda: %q", out.String())
	}
}
