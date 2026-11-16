package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"io"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

func runTTY(t *testing.T, args ...string) string {
	t.Helper()
	outIsTTY = func(io.Writer) bool { return true }
	defer func() { outIsTTY = func(io.Writer) bool { return false } }()
	var out bytes.Buffer
	if err := run(append([]string{"--lang", "es"}, args...), strings.NewReader(""), &out); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestColorOnTTYHonorsOptOuts(t *testing.T) {
	startCore(t)
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm")
	if out := runTTY(t, "calc", "subnet", "10.0.0.0/24"); !strings.Contains(out, "\x1b[") {
		t.Fatalf("sin color en TTY: %q", out)
	}
	if out := runTTY(t, "calc", "subnet", "10.0.0.0/24", "--no-color"); strings.Contains(out, "\x1b[") {
		t.Fatalf("--no-color ignorado: %q", out)
	}
	t.Setenv("NO_COLOR", "1")
	if out := runTTY(t, "calc", "subnet", "10.0.0.0/24"); strings.Contains(out, "\x1b[") {
		t.Fatalf("NO_COLOR ignorado: %q", out)
	}
	t.Setenv("NO_COLOR", "")
	if out := must(t, "", "calc", "subnet", "10.0.0.0/24"); strings.Contains(out, "\x1b[") {
		t.Fatalf("color sin TTY: %q", out)
	}
}

func TestColorUsesSavedPalette(t *testing.T) {
	startCore(t)
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "xterm")
	t.Setenv("COLORTERM", "truecolor")
	conn, err := ipc.Dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := v1.NewPrefsServiceClient(conn).SetPreference(ctx(), &v1.SetPreferenceRequest{Key: "terminal", Value: `{"palette":"p3"}`}); err != nil {
		t.Fatal(err)
	}
	out := runTTY(t, "calc", "subnet", "10.0.0.0/24")
	if !strings.Contains(out, "\x1b[38;2;246;81;246m") { // addr (magenta) de P3
		t.Fatalf("sin truecolor: %q", out)
	}
}

func TestNoColorWithoutCommandDoesNotPanic(t *testing.T) {
	if err := run([]string{"--no-color"}, strings.NewReader(""), io.Discard); err == nil {
		t.Fatal("se esperaba error de uso")
	}
}
