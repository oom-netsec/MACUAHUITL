package transfer

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestCleanSaneaControlYFormato(t *testing.T) {
	// "\x1b[2J" borra la terminal; U+202E invierte el texto: ninguno debe salir tal cual.
	got := clean("a\x1b[2Jb\u202ec\u200bd\té")
	if strings.ContainsAny(got, "\x1b\u202e\u200b\t") || got != "a?[2Jb?c?d?é" {
		t.Fatalf("clean = %q", got)
	}
}

func TestLineaDeSesion(t *testing.T) {
	cli.SetLang("en")
	t.Cleanup(func() { cli.SetLang("") })
	act := &v1.TransferSession{State: "active", ServerId: "srv1", Protocol: "tftp", Client: "10.0.0.2:69", Direction: "out", Name: "a\x1b[2J.bin", Bytes: 512, Total: 2048, BytesPerSec: 100}
	if got, want := sessionLine(act), "active  srv1  tftp  10.0.0.2:69  out  a?[2J.bin  512/2048 (25%)  100 B/s"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	sin := &v1.TransferSession{State: "failed", ServerId: "srv1", Protocol: "ftp", Client: "c", Direction: "in", Name: "n", Bytes: 7, Error: "boom\u202e"}
	if got, want := sessionLine(sin), "failed  srv1  ftp  c  in  n  7/0  0 B/s  boom?"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestStatusConRechazos(t *testing.T) {
	cli.SetLang("es")
	t.Cleanup(func() { cli.SetLang("") })
	now := time.UnixMilli(100_000)
	var b bytes.Buffer
	renderStatus(&b, &v1.ListTransferSessionsResponse{
		Sessions:   []*v1.TransferSession{{State: "done", ServerId: "s", Protocol: "http", Client: "c", Direction: "out", Name: "x", Bytes: 10, Total: 10}},
		Rejections: []*v1.TransferRejection{{Ip: "1.2.3.4", Protocol: "tftp", Cause: "not_found", Count: 3, Last: 95_000, Name: "\x1b[2J"}},
	}, now)
	want := "done  s  http  c  out  x  10/10 (100%)  0 B/s\nrechazos:\n1.2.3.4  tftp  not_found  ×3  hace 5 s  ?[2J\n"
	if b.String() != want {
		t.Fatalf("got %q want %q", b.String(), want)
	}
	b.Reset()
	renderStatus(&b, &v1.ListTransferSessionsResponse{}, now)
	if b.String() != "no hay sesiones\n" {
		t.Fatalf("vacío: %q", b.String())
	}
}

func TestLineaDeServeIdioma(t *testing.T) {
	t.Cleanup(func() { cli.SetLang("") })
	tr := transferEvent{Proto: "tftp", Dir: "lectura", DirCode: "read", Client: "172.30.0.2:49989", File: "c3560-test.bin", Bytes: 30, Result: "ok"}
	at := time.Date(2026, 1, 2, 8, 9, 59, 0, time.Local)
	for lang, want := range map[string]string{
		"":   "08:09:59  tftp read 172.30.0.2:49989  c3560-test.bin  30 bytes  0s  ok ",
		"es": "08:09:59  tftp lectura 172.30.0.2:49989  c3560-test.bin  30 bytes  0s  ok ",
	} {
		cli.SetLang(lang)
		if got := serveLine(tr, at, cli.T); got != want {
			t.Errorf("%q: got %q want %q", lang, got, want)
		}
	}
	// Sin DirCode (núcleo viejo) se deduce de Dir.
	tr.DirCode = ""
	tr.Dir = "escritura"
	tr.Result = "error"
	tr.File = "x\x1b[2J"
	cli.SetLang("en")
	if got := serveLine(tr, at, cli.T); got != "08:09:59  tftp write 172.30.0.2:49989  x?[2J  30 bytes  0s  error " {
		t.Errorf("got %q", got)
	}
}

func TestProgresoImprimeSoloActivas(t *testing.T) {
	cli.SetLang("en")
	t.Cleanup(func() { cli.SetLang("") })
	var b bytes.Buffer
	n := 0
	ctx, cancel := context.WithCancel(context.Background())
	list := func() (*v1.ListTransferSessionsResponse, error) {
		if n++; n == 2 {
			cancel()
		}
		return &v1.ListTransferSessionsResponse{Sessions: []*v1.TransferSession{
			{State: "active", ServerId: "s", Protocol: "ftp", Client: "c", Direction: "in", Name: "n\x1b[2J", Bytes: 1},
			{State: "done", ServerId: "s", Protocol: "ftp", Client: "c", Direction: "in", Name: "fin"},
		}}, nil
	}
	progressLoop(ctx, "progress", time.Millisecond, list, &b)
	out := b.String()
	if !strings.Contains(out, "progress  active  s  ftp  c  in  n?[2J  1/0  0 B/s") || strings.Contains(out, "fin") || strings.ContainsAny(out, "\x1b") {
		t.Fatalf("salida: %q", out)
	}
}
