package flows

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
)

func TestFlowRecordLines(t *testing.T) {
	r := Record{Time: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC), Flow: Flow{Exporter: "10.0.0.9", Src: "10.0.0.1", Dst: "2001:db8::2", SrcPort: 51000, DstPort: 443, Proto: 6, Bytes: 1500, Packets: 10}}
	const text = "tcp 10.0.0.1:51000 -> [2001:db8::2]:443 bytes=1500 packets=10 exp=10.0.0.9"
	if got := r.Text(); got != text {
		t.Fatalf("Text = %q", got)
	}
	if got := (Flow{Src: "10.0.0.1", Dst: "10.0.0.2", Proto: 1, Exporter: "e"}).Text(); got != "icmp 10.0.0.1 -> 10.0.0.2 bytes=0 packets=0 exp=e" {
		t.Fatalf("sin puertos = %q", got)
	}
	if got := string(r.Line("texto")); got != "2026-11-07T12:00:00Z 10.0.0.9 "+text+"\n" {
		t.Fatalf("texto = %q", got)
	}
	if got := string(r.Line("")); got != string(r.Line("texto")) {
		t.Fatalf("el default es texto: %q", got)
	}
	if got := string(r.Line("crudo")); got != text+"\n" {
		t.Fatalf("crudo = %q", got)
	}
	if got := string(r.Line("jsonl")); !strings.HasPrefix(got, `{"Time":"2026-11-07T12:00:00Z","Exporter":"10.0.0.9","Src":"10.0.0.1"`) || !strings.HasSuffix(got, "}\n") {
		t.Fatalf("jsonl = %q", got)
	}
	if r.Origin() != "10.0.0.9" {
		t.Fatalf("origen = %q", r.Origin())
	}
}

// start arranca Listen y devuelve la dirección y el cierre, que da el resumen final.
func start(t *testing.T, cfg Config) (addr string, stop func() (Snapshot, error)) {
	t.Helper()
	ready := make(chan string, 1)
	cfg.Addr = "127.0.0.1:0"
	cfg.OnListening = func(a string) { ready <- a }
	ctx, cancel := context.WithCancel(context.Background())
	type res struct {
		s   Snapshot
		err error
	}
	done := make(chan res, 1)
	go func() { s, err := Listen(ctx, cfg); done <- res{s, err} }()
	select {
	case addr = <-ready:
	case r := <-done:
		t.Fatal(r.err)
	}
	var once sync.Once
	var out res
	stop = func() (Snapshot, error) {
		once.Do(func() { cancel(); out = <-done })
		return out.s, out.err
	}
	t.Cleanup(func() { stop() })
	return addr, stop
}

// sendFrom manda n datagramas NetFlow v5 de un registro desde la IP local indicada.
func sendFrom(t *testing.T, addr, ip string, n int) {
	t.Helper()
	raddr, _ := net.ResolveUDPAddr("udp", addr)
	c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)}, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pkt := netflowV5(1)
	for range n {
		if _, err := c.Write(pkt); err != nil {
			t.Fatal(err)
		}
	}
}

func ls(dir string) []string {
	fs, _ := filepath.Glob(filepath.Join(dir, "*"))
	return fs
}

func readAll(t *testing.T, dir string) string {
	t.Helper()
	var sb strings.Builder
	for _, f := range ls(dir) {
		b, _ := os.ReadFile(f)
		sb.Write(b)
	}
	return sb.String()
}

// Una ráfaga de un exportador no le quita lugar a otro, y los descartes se cuentan por origen.
func TestListenFloodFromOneExporterLeavesRoomForAnother(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "flows")
	var mu sync.Mutex
	var last ingest.Drops
	addr, stop := start(t, Config{Limits: ingest.Limits{PerSource: 1, PerSourceBurst: 3, Global: 1000}, Sink: &ingest.Sink{Dir: dir, Template: "f_{fecha}", MaxFiles: 5, Format: "crudo"},
		OnDrops: func(d ingest.Drops) { mu.Lock(); last = d; mu.Unlock() }})
	sendFrom(t, addr, "127.0.0.1", 60)
	sendFrom(t, addr, "127.0.0.2", 2)
	time.Sleep(1300 * time.Millisecond) // el reporte de descartes es cada segundo
	s, err := stop()
	if err != nil {
		t.Fatal(err)
	}
	body := readAll(t, dir)
	if got := strings.Count(body, "exp=127.0.0.2"); got != 2 || s.Flows < 5 || s.Flows > 8 {
		t.Fatalf("flujos=%d del otro exportador=%d\n%s", s.Flows, got, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if last.PorOrigen < 50 || last.Top[0].Source != "127.0.0.1" || last.Top[0].Count != last.Total {
		t.Fatalf("descartes = %+v", last)
	}
}

// slowOut es un Out atascado hasta que se libere.
type slowOut struct{ release chan struct{} }

func (s slowOut) Write(p []byte) (int, error) { <-s.release; return len(p), nil }

var _ io.Writer = slowOut{}

// Con la cola llena el lector sigue leyendo y los descartes se cuentan (el resumen sigue creciendo).
func TestListenFullQueueDoesNotBlockReader(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	var mu sync.Mutex
	var last ingest.Drops
	addr, stop := start(t, Config{Limits: ingest.Limits{PerSource: 10000, Global: 100000, Queue: 64}, Out: slowOut{release},
		OnDrops: func(d ingest.Drops) { mu.Lock(); last = d; mu.Unlock() }})
	t.Cleanup(free) // se registra después de start: corre antes que su cierre, que espera al consumidor atascado
	sendFrom(t, addr, "127.0.0.1", 400)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := last.ColaLlena
		mu.Unlock()
		if n >= 100 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	d := last
	mu.Unlock()
	if d.ColaLlena < 100 || d.ColaLlena != d.Total {
		t.Fatalf("con el consumidor atascado debía descartar por cola llena: %+v", d)
	}
	free()
	if s, err := stop(); err != nil || s.Flows < d.ColaLlena+64 {
		t.Fatalf("el resumen cuenta lo que llegó aunque el archivo se atrase: %+v %v", s, err)
	}
}

func TestListenSinkFormatsRotationAndRetention(t *testing.T) {
	for format, check := range map[string]func(string) bool{
		"texto": func(b string) bool {
			return strings.Contains(b, " 127.0.0.1 tcp 10.0.0.1:51000 -> 10.0.0.2:443 bytes=1500 packets=10")
		},
		"crudo": func(b string) bool {
			return strings.HasPrefix(b, "tcp 10.0.0.1:51000 -> 10.0.0.2:443 bytes=1500 packets=10 exp=127.0.0.1\n")
		},
		"jsonl": func(b string) bool {
			return strings.HasPrefix(b, `{"Time":`) && strings.Contains(b, `"Dst":"10.0.0.2"`)
		},
	} {
		dir := filepath.Join(t.TempDir(), "flows")
		addr, stop := start(t, Config{Sink: &ingest.Sink{Dir: dir, Template: "flujos_{fecha}_{hora}", MaxFiles: 5, Format: format}})
		sendFrom(t, addr, "127.0.0.1", 1)
		time.Sleep(300 * time.Millisecond)
		if _, err := stop(); err != nil {
			t.Fatal(err)
		}
		fs := ls(dir)
		ext := ".log"
		if format == "jsonl" {
			ext = ".jsonl"
		}
		if len(fs) != 1 || !strings.HasSuffix(fs[0], ext) {
			t.Fatalf("%s: archivos %v", format, fs)
		}
		if b := readAll(t, dir); !check(b) {
			t.Errorf("%s: %q", format, b)
		}
		if st, _ := os.Stat(fs[0]); st.Mode().Perm() != 0o600 {
			t.Errorf("%s: permisos %v", format, st.Mode())
		}
	}
	dir := filepath.Join(t.TempDir(), "flows")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "notas.log"), []byte("mío"), 0o600)
	var clock atomic.Int64
	clock.Store(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).UnixNano())
	var removed []string
	var mu sync.Mutex
	addr, stop := start(t, Config{Now: func() time.Time { return time.Unix(0, clock.Load()).UTC() },
		Sink: &ingest.Sink{Dir: dir, Template: "flujos_{fecha}_{hora}", MaxFiles: 2, RotateEvery: time.Minute, Format: "crudo",
			OnRemove: func(p string) { mu.Lock(); removed = append(removed, filepath.Base(p)); mu.Unlock() }}})
	for range 4 {
		sendFrom(t, addr, "127.0.0.1", 1)
		time.Sleep(200 * time.Millisecond)
		clock.Add(int64(2 * time.Minute))
	}
	if _, err := stop(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if got := ls(dir); len(got) != 3 || len(removed) != 2 { // notas.log + los 2 que se conservan; se borraron 2 de 4
		t.Fatalf("archivos=%v borrados=%v", got, removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "notas.log")); err != nil {
		t.Fatal("la retención borró un archivo ajeno")
	}
}

// Si el archivo falla (el disco «desaparece»), la escucha termina con el error en vez de seguir en silencio.
func TestListenStopsWhenSinkFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "flows")
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := Listen(context.Background(), Config{Addr: "127.0.0.1:0", OnListening: func(a string) { ready <- a },
			Sink: &ingest.Sink{Dir: dir, Template: "t_{fecha}", MaxFiles: 5}})
		done <- err
	}()
	addr := <-ready
	os.RemoveAll(dir)
	sendFrom(t, addr, "127.0.0.1", 1)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "archivo de salida") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("la escucha siguió con el archivo roto")
	}
}

func TestListenRejectsBadLimitsAndSink(t *testing.T) {
	for name, c := range map[string]Config{
		"limits": {Addr: "127.0.0.1:0", Limits: ingest.Limits{Queue: 3}},
		"sink":   {Addr: "127.0.0.1:0", Sink: &ingest.Sink{Dir: t.TempDir(), Template: "../x", MaxFiles: 5}},
	} {
		if _, err := Listen(context.Background(), c); err == nil {
			t.Errorf("%s: debía rechazarse", name)
		}
	}
}

// Sin archivo no hay a qué protegerle la escritura: el tope no se aplica y el resumen cuenta todo lo que llegó.
func TestListenWithoutSinkAppliesNoRateLimit(t *testing.T) {
	var drops atomic.Int64
	addr, stop := start(t, Config{Limits: ingest.Limits{PerSource: 1, PerSourceBurst: 1}, OnDrops: func(ingest.Drops) { drops.Add(1) }})
	sendFrom(t, addr, "127.0.0.1", 20)
	time.Sleep(500 * time.Millisecond)
	s, _ := stop()
	if s.Flows != 20 || drops.Load() != 0 {
		t.Fatalf("flujos=%d reportes de descartes=%d", s.Flows, drops.Load())
	}
}
