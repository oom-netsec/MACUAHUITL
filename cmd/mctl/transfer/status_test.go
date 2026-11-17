package transfer

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestCleanSaneaControlYFormato(t *testing.T) {
	// "\x1b[2J" borra la terminal; U+202E invierte el texto: ninguno debe salir tal cual.
	got := clean("a\x1b[2Jb\u202ec\u200bd\té\u2028")
	if strings.ContainsAny(got, "\x1b\u202e\u200b\t\u2028") || got != "a?[2Jb?c?d?é?" {
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

// Cada campo de texto que llega del núcleo pasa por clean antes de salir.
func TestSaneadoCampoPorCampo(t *testing.T) {
	cli.SetLang("en")
	t.Cleanup(func() { cli.SetLang("") })
	const esc = "\x1b[31m"
	fill := func(v any) {
		e := reflect.ValueOf(v).Elem()
		for i := 0; i < e.NumField(); i++ {
			if f := e.Field(i); f.Kind() == reflect.String && f.CanSet() {
				f.SetString(esc)
			}
		}
	}
	s, j := &v1.TransferSession{Bytes: 1, Total: 2}, &v1.TransferRejection{Count: 1}
	fill(s)
	fill(j)
	var b bytes.Buffer
	renderStatus(&b, &v1.ListTransferSessionsResponse{Sessions: []*v1.TransferSession{s}, Rejections: []*v1.TransferRejection{j}}, time.Now())
	if strings.Contains(b.String(), "\x1b") || strings.Count(b.String(), "?[31m") < 11 {
		t.Fatalf("status: %q", b.String())
	}
	var ev transferEvent
	fill(&ev)
	ev.Rejected = true
	for _, lang := range []string{"en", "es"} {
		cli.SetLang(lang)
		if out := serveLine(ev, time.Now(), cli.T); strings.Contains(out, "\x1b") || !strings.Contains(out, "?[31m") {
			t.Fatalf("serve %s: %q", lang, out)
		}
	}
}

func TestLineaDeServeCodigoManda(t *testing.T) {
	cli.SetLang("en")
	t.Cleanup(func() { cli.SetLang("") })
	// DirCode manda aunque Dir diga otra cosa.
	if got := serveLine(transferEvent{Proto: "ftp", Dir: "escritura", DirCode: "read"}, time.Now(), cli.T); !strings.Contains(got, "ftp read ") {
		t.Fatal(got)
	}
}

func TestProgresoSigueTrasUnError(t *testing.T) {
	var n int
	ctx, cancel := context.WithCancel(context.Background())
	list := func() (*v1.ListTransferSessionsResponse, error) {
		if n++; n == 1 {
			return nil, context.DeadlineExceeded
		}
		cancel()
		return &v1.ListTransferSessionsResponse{Sessions: []*v1.TransferSession{{State: "active", Name: "n"}}}, nil
	}
	var b bytes.Buffer
	progressLoop(ctx, "progress", time.Millisecond, list, &b)
	if !strings.Contains(b.String(), "progress  active") {
		t.Fatalf("no reintentó: %q", b.String())
	}
}

// Dos bucles de avance y el del stream comparten el lockedWriter; con -race lo demuestra.
func TestLockedWriterSerializa(t *testing.T) {
	var b bytes.Buffer
	out := &lockedWriter{w: &b}
	list := func() (*v1.ListTransferSessionsResponse, error) {
		return &v1.ListTransferSessionsResponse{Sessions: []*v1.TransferSession{{State: "active", Name: "n"}}}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); progressLoop(ctx, "progress", time.Millisecond, list, out) }()
	}
	for range 50 {
		out.Write([]byte("fin\n"))
	}
	wg.Wait()
	for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if l != "fin" && !strings.HasPrefix(l, "progress  active") {
			t.Fatalf("línea mezclada: %q", l)
		}
	}
}

func TestLineasSaneadas(t *testing.T) {
	if got := cleanLines("a\x1b[2J\nb\u202e\n"); got != "a?[2J\nb?\n" {
		t.Fatalf("%q", got)
	}
}
