package snmp

import (
	"bytes"
	"context"
	"encoding/hex"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/snmp/snmptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
)

func TestTrapTextIsOneLine(t *testing.T) {
	tr := Trap{Time: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC), From: "10.0.0.1:50000", Version: "2c", Name: "linkDown", TrapOID: ".1.3.6.1.6.3.1.1.5.3",
		Summary: "linkDown Gi1/0/7 oper down", Vars: []Var{{OID: ".1.3.6.1.2.1.2.2.1.2.7", Type: "OctetString", Value: "Gi1/0/7\nlinea2\x1b[0m"}}}
	got := tr.Text()
	if got != "v2c linkDown Gi1/0/7 oper down .1.3.6.1.2.1.2.2.1.2.7=Gi1/0/7.linea2.[0m" {
		t.Fatalf("Text = %q", got)
	}
	if got := (Trap{Version: "2c", Inform: true, Name: "coldStart"}).Text(); got != "v2c inform coldStart" {
		t.Fatalf("inform = %q", got)
	}
	if got := (Trap{Error: "paquete vacío\nx", Raw: "3000"}).Text(); got != "error: paquete vacío.x raw=3000" {
		t.Fatalf("error = %q", got)
	}
	if got := string(tr.Line("texto")); got != "2026-11-07T12:00:00Z 10.0.0.1:50000 "+tr.Text()+"\n" {
		t.Fatalf("texto = %q", got)
	}
	if got := string(tr.Line("crudo")); got != tr.Text()+"\n" {
		t.Fatalf("crudo = %q", got)
	}
	if got := string(tr.Line("jsonl")); !strings.HasPrefix(got, `{"Time":"2026-11-07T12:00:00Z","From":"10.0.0.1:50000"`) || !strings.HasSuffix(got, "}\n") || strings.Count(got, "\n") != 1 {
		t.Fatalf("jsonl = %q", got)
	}
}

// sendFrom manda n traps desde la IP local indicada (127.0.0.x), cada uno con su socket.
func sendFrom(t *testing.T, addr, ip string, n int) {
	t.Helper()
	x := sender(t, addr, gosnmp.Version2c, func(x *gosnmp.GoSNMP) { x.LocalAddr = ip + ":0" })
	for range n {
		if _, err := x.SendTrap(gosnmp.SnmpTrap{Variables: linkDown}); err != nil {
			t.Fatal(err)
		}
	}
}

// Una ráfaga de un origen no le quita lugar a otro, y los descartes se cuentan por origen.
func TestTrapsFloodFromOneSourceLeavesRoomForAnother(t *testing.T) {
	var mu sync.Mutex
	var last ingest.Drops
	addr, sink := startTraps(t, TrapConfig{Limits: ingest.Limits{PerSource: 1, PerSourceBurst: 3, Global: 1000},
		OnDrops: func(d ingest.Drops) { mu.Lock(); last = d; mu.Unlock() }})
	sendFrom(t, addr, "127.0.0.1", 60)
	sendFrom(t, addr, "127.0.0.2", 2)
	deadline := time.Now().Add(3 * time.Second)
	var from1, from2 int
	for time.Now().Before(deadline) && from2 < 2 {
		time.Sleep(20 * time.Millisecond)
		sink.mu.Lock()
		from1, from2 = 0, 0
		for _, tr := range sink.traps {
			if strings.HasPrefix(tr.From, "127.0.0.2:") {
				from2++
			} else {
				from1++
			}
		}
		sink.mu.Unlock()
	}
	if from2 != 2 || from1 < 3 || from1 > 6 {
		t.Fatalf("pasaron %d del inundador y %d del otro", from1, from2)
	}
	time.Sleep(1200 * time.Millisecond) // el reporte de descartes es cada segundo
	mu.Lock()
	defer mu.Unlock()
	if last.PorOrigen < 50 || last.Top[0].Source != "127.0.0.1" || last.Top[0].Count != last.Total {
		t.Fatalf("descartes = %+v", last)
	}
}

// listenWith arranca ListenTraps con la config tal cual (startTraps pisa OnTrap) y devuelve la dirección y el cierre.
func listenWith(t *testing.T, cfg TrapConfig) (addr string, stop func() error) {
	t.Helper()
	ready := make(chan string, 1)
	cfg.Addr = "127.0.0.1:0"
	cfg.OnListening = func(a string) { ready <- a }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ListenTraps(ctx, cfg) }()
	select {
	case addr = <-ready:
	case err := <-done:
		t.Fatal(err)
	}
	var once sync.Once
	stop = func() (err error) {
		once.Do(func() { cancel(); err = <-done })
		return err
	}
	t.Cleanup(func() { stop() })
	return addr, stop
}

// Con la cola llena el lector sigue leyendo (el consumidor atascado no lo frena) y cuenta «cola_llena».
func TestTrapsFullQueueDoesNotBlockReader(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var last ingest.Drops
	addr, stop := listenWith(t, TrapConfig{Limits: ingest.Limits{PerSource: 10000, Global: 100000, Queue: 64},
		OnTrap:  func(Trap) { <-release },
		OnDrops: func(d ingest.Drops) { mu.Lock(); last = d; mu.Unlock() }})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	t.Cleanup(free) // corre antes que el cierre de listenWith, que espera al consumidor atascado
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
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

func readOnly(t *testing.T, dir, glob string) []string {
	t.Helper()
	fs, _ := filepath.Glob(filepath.Join(dir, glob))
	return fs
}

// Los tres formatos llegan al archivo; la retención solo borra lo que encaja con la plantilla y la rotación cambia de archivo.
func TestTrapsSinkFormatsRotationAndRetention(t *testing.T) {
	for format, check := range map[string]func(string) bool{
		"texto": func(b string) bool {
			return strings.Contains(b, " 127.0.0.1:") && strings.Contains(b, " v2c linkDown ") && strings.HasSuffix(b, "\n")
		},
		"crudo": func(b string) bool { return strings.HasPrefix(b, "v2c linkDown ") },
		"jsonl": func(b string) bool {
			return strings.HasPrefix(b, `{"Time":`) && strings.Contains(b, `"Name":"linkDown"`)
		},
	} {
		dir := filepath.Join(t.TempDir(), "traps")
		addr, stop := listenWith(t, TrapConfig{Sink: &ingest.Sink{Dir: dir, Template: "traps_{fecha}_{hora}", MaxFiles: 5, Format: format}, OnTrap: func(Trap) {}})
		sendFrom(t, addr, "127.0.0.1", 1)
		time.Sleep(300 * time.Millisecond)
		if err := stop(); err != nil {
			t.Fatal(err)
		}
		ext := ".log"
		if format == "jsonl" {
			ext = ".jsonl"
		}
		fs := readOnly(t, dir, "traps_*"+ext)
		if len(fs) != 1 {
			t.Fatalf("%s: archivos %v", format, fs)
		}
		if b, _ := os.ReadFile(fs[0]); !check(string(b)) {
			t.Errorf("%s: %q", format, b)
		}
		if st, _ := os.Stat(fs[0]); st.Mode().Perm() != 0o600 {
			t.Errorf("%s: permisos %v", format, st.Mode())
		}
	}
	dir := filepath.Join(t.TempDir(), "traps")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "notas.log"), []byte("mío"), 0o600)
	var clock atomic.Int64
	clock.Store(time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC).UnixNano())
	var removed []string
	var mu sync.Mutex
	addr, stop := listenWith(t, TrapConfig{Now: func() time.Time { return time.Unix(0, clock.Load()).UTC() }, OnTrap: func(Trap) {},
		Sink: &ingest.Sink{Dir: dir, Template: "traps_{fecha}_{hora}", MaxFiles: 2, RotateEvery: time.Minute, Format: "crudo",
			OnRemove: func(p string) { mu.Lock(); removed = append(removed, filepath.Base(p)); mu.Unlock() }}})
	for range 4 {
		sendFrom(t, addr, "127.0.0.1", 1)
		time.Sleep(200 * time.Millisecond)
		clock.Add(int64(2 * time.Minute))
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	got := readOnly(t, dir, "*")
	if len(got) != 3 || len(removed) != 2 { // notas.log + los 2 que se conservan; se borraron 2 de 4
		t.Fatalf("archivos=%v borrados=%v", got, removed)
	}
	if _, err := os.Stat(filepath.Join(dir, "notas.log")); err != nil {
		t.Fatal("la retención borró un archivo ajeno")
	}
}

// Si el archivo falla (el disco «desaparece»), la escucha termina con el error en vez de seguir en silencio.
func TestTrapsStopsWhenSinkFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "traps")
	ready := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- ListenTraps(context.Background(), TrapConfig{Addr: "127.0.0.1:0", OnListening: func(a string) { ready <- a },
			Sink: &ingest.Sink{Dir: dir, Template: "t_{fecha}", MaxFiles: 5}})
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

func TestTrapsRejectBadLimitsAndSink(t *testing.T) {
	for name, c := range map[string]TrapConfig{
		"limits": {Addr: "127.0.0.1:0", Limits: ingest.Limits{Queue: 3}},
		"sink":   {Addr: "127.0.0.1:0", Sink: &ingest.Sink{Dir: t.TempDir(), Template: "../x", MaxFiles: 5}},
	} {
		if err := ListenTraps(context.Background(), c); err == nil {
			t.Errorf("%s: debía rechazarse", name)
		}
	}
}

// Con la cola llena un inform descartado no se responde: si se respondiera, el equipo creería entregado un trap que se perdió.
func TestTrapsInformNotAnsweredWhenQueueFull(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	free := func() { once.Do(func() { close(release) }) }
	addr, stop := listenWith(t, TrapConfig{Limits: ingest.Limits{PerSource: 10000, Global: 100000, Queue: 64}, OnTrap: func(Trap) { <-release }})
	t.Cleanup(free)
	sendFrom(t, addr, "127.0.0.1", 200) // llena la cola
	time.Sleep(300 * time.Millisecond)
	x := sender(t, addr, gosnmp.Version2c)
	x.Timeout, x.Retries = 500*time.Millisecond, 0
	if _, err := x.SendTrap(gosnmp.SnmpTrap{Variables: linkDown, IsInform: true}); err == nil {
		t.Fatal("el inform se respondió aunque se descartó por cola llena")
	}
	free()
	if err := stop(); err != nil {
		t.Fatal(err)
	}
}

// Un trap v3 que no se decodifica no puede dejar su paquete (con el usuario USM y los parámetros de autenticación,
// que sirven para atacar la clave sin conexión) ni en los eventos ni en el archivo, en ningún formato.
func TestTrapV3UndecodedNeverKeepsPacket(t *testing.T) {
	const user = "usuario-usm-secreto"
	for _, c := range []struct {
		name string
		v3   *Target
	}{{"sin credencial", nil}, {"usuario distinto", &Target{User: "noc", AuthProto: "SHA", AuthPass: "authpass123", PrivProto: "AES", PrivPass: "privpass123"}}} {
		for _, format := range []string{"texto", "crudo", "jsonl"} {
			dir := filepath.Join(t.TempDir(), "traps")
			var out bytes.Buffer
			var mu sync.Mutex
			sink := &trapSink{}
			addr, stop := listenWith(t, TrapConfig{V3: c.v3, Out: lockedWriter{&mu, &out}, OnTrap: sink.add, Sink: &ingest.Sink{Dir: dir, Template: "t_{fecha}", MaxFiles: 5, Format: format}})
			x := sender(t, addr, gosnmp.Version3, func(x *gosnmp.GoSNMP) {
				x.SecurityModel, x.MsgFlags = gosnmp.UserSecurityModel, gosnmp.AuthPriv
				x.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: user, AuthoritativeEngineID: snmptest.EngineID, AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: 50,
					AuthenticationProtocol: gosnmp.SHA, AuthenticationPassphrase: "otra-clave-1", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "otra-clave-2"}
			})
			x.SendTrap(gosnmp.SnmpTrap{Variables: linkDown})
			tr := sink.wait(t, 1)[0]
			stop()
			if tr.Error == "" || !strings.HasPrefix(tr.Error, "v3 sin decodificar (") || tr.Raw != "" || tr.Version != "3" {
				t.Fatalf("%s/%s: trap = %+v", c.name, format, tr)
			}
			all := tr.Text() + string(tr.Line("jsonl"))
			for _, b := range files(t, dir) {
				all += b
			}
			mu.Lock()
			all += out.String()
			mu.Unlock()
			if strings.Contains(all, user) || strings.Contains(all, hex.EncodeToString([]byte(user))) || !strings.Contains(all, "v3 sin decodificar (") {
				t.Fatalf("%s/%s: salida:\n%s", c.name, format, all)
			}
		}
	}
}

func files(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	fs, _ := filepath.Glob(filepath.Join(dir, "*"))
	for _, f := range fs {
		b, _ := os.ReadFile(f)
		out = append(out, string(b))
	}
	return out
}
