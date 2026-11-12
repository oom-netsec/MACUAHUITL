package syslogd

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSubmitCopiesTheBuffer(t *testing.T) {
	p := newPipeline(Config{Limits: Limits{Queue: 4}}, nil, func() {})
	buf := []byte("<14>uno")
	p.submit("10.0.0.1:1", buf, false)
	copy(buf, "XXXXXXX") // el lector UDP reutiliza el búfer
	if got := string((<-p.Queue()).raw); got != "<14>uno" {
		t.Fatalf("la cola guardó una referencia al búfer: %q", got)
	}
}

func TestListenReportsDropsOnlyWhenTheyChange(t *testing.T) {
	old := dropInterval
	dropInterval = 20 * time.Millisecond
	t.Cleanup(func() { dropInterval = old })
	var mu sync.Mutex
	var calls []Drops
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Listen(ctx, Config{Addr: "127.0.0.1:0", Limits: Limits{PerSource: 1, PerSourceBurst: 1},
			OnListening: func(a string) { addr <- a },
			OnDrops:     func(d Drops) { mu.Lock(); calls = append(calls, d); mu.Unlock() }})
	}()
	c, _ := net.Dial("udp", <-addr)
	defer c.Close()
	for range 30 {
		c.Write([]byte("<14>flood"))
	}
	count := func() (int, Drops) {
		mu.Lock()
		defer mu.Unlock()
		if len(calls) == 0 {
			return 0, Drops{}
		}
		return len(calls), calls[len(calls)-1]
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if n, d := count(); n > 0 && d.Total >= 20 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	n, d := count()
	if n == 0 || d.Total == 0 || d.PorOrigen != d.Total || d.Desde.IsZero() || len(d.Top) != 1 || d.Top[0].Source != "127.0.0.1" || d.Top[0].Count != d.Total {
		t.Fatalf("n=%d drops=%+v", n, d)
	}
	time.Sleep(200 * time.Millisecond)
	if n2, _ := count(); n2 != n {
		t.Fatalf("se reportó sin cambios: %d -> %d llamadas", n, n2)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if n3, d3 := count(); n3 != n+1 || d3.Total != d.Total {
		t.Fatalf("falta la llamada final: %d -> %d (%+v)", n, n3, d3)
	}
}

func TestListenWritesSinkAndRejectsBadConfig(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	var opened []string
	var mu sync.Mutex
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	addr := make(chan string, 1)
	done := make(chan error, 1)
	s := &sink{}
	go func() {
		done <- Listen(ctx, Config{Addr: "127.0.0.1:0", OnListening: func(a string) { addr <- a }, OnMessage: s.on,
			Sink: &Sink{Dir: dir, Template: "t_{fecha}_{hora}", MaxFiles: 5, Format: "crudo", OnOpen: func(p string) { mu.Lock(); opened = append(opened, p); mu.Unlock() }}})
	}()
	c, _ := net.Dial("udp", <-addr)
	defer c.Close()
	c.Write([]byte("<14>a guardar"))
	s.wait(t, 1)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(opened) != 1 {
		t.Fatalf("abiertos = %v", opened)
	}
	if b, _ := os.ReadFile(opened[0]); string(b) != "<14>a guardar\n" {
		t.Fatalf("archivo = %q", b)
	}
	for name, c := range map[string]Config{
		"limits": {Addr: "127.0.0.1:0", Limits: Limits{Queue: 3}},
		"sink":   {Addr: "127.0.0.1:0", Sink: &Sink{Dir: dir, Template: "../x", MaxFiles: 5}},
	} {
		if err := Listen(context.Background(), c); err == nil {
			t.Errorf("%s: debía rechazarse", name)
		}
	}
}

func TestListenStopsWhenSinkFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	addr := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		done <- Listen(context.Background(), Config{Addr: "127.0.0.1:0", OnListening: func(a string) { addr <- a },
			Sink: &Sink{Dir: dir, Template: "t_{fecha}", MaxFiles: 5}})
	}()
	a := <-addr
	os.RemoveAll(dir) // el disco «desaparece» a media escucha
	c, _ := net.Dial("udp", a)
	defer c.Close()
	c.Write([]byte("<14>x"))
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "archivo de salida") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("la escucha siguió con el archivo roto")
	}
}

func TestListenWithoutDropsNeverCallsOnDrops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	addr := make(chan string, 1)
	done := make(chan error, 1)
	s := &sink{}
	calls := 0
	go func() {
		done <- Listen(ctx, Config{Addr: "127.0.0.1:0", OnListening: func(a string) { addr <- a }, OnMessage: s.on, OnDrops: func(Drops) { calls++ }})
	}()
	c, _ := net.Dial("udp", <-addr)
	defer c.Close()
	c.Write([]byte("<14>uno"))
	s.wait(t, 1)
	cancel()
	<-done
	if calls != 0 {
		t.Fatalf("OnDrops sin descartes: %d llamadas", calls)
	}
}
