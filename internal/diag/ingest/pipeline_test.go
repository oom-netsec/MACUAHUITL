package ingest

import (
	"os"
	"sync"
	"testing"
	"time"
)

// submit es lo que hace un lector: tope de tasa y cola, sin esperar.
func submit[T any](p *Pipeline[T], from string, v T) {
	if key, ok := p.Admit(from); ok {
		p.Enqueue(key, v)
	}
}

func TestSubmitNeverBlocksWhenQueueFull(t *testing.T) {
	r := newReloj()
	p := NewPipeline(PipelineConfig[string]{Limits: Limits{PerSource: 10000, Global: 100000, Queue: 4}, Now: r.Now})
	done := make(chan struct{})
	go func() { // el consumidor está detenido: nadie vacía la cola
		for range 100 {
			submit(p, "10.0.0.1:1000", "x")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("el lector se bloqueó con la cola llena")
	}
	d := p.drops.snapshot()
	if len(p.q) != 4 || d.ColaLlena != 96 || d.Total != 96 || d.Top[0] != (SourceDrops{"10.0.0.1", 96}) {
		t.Fatalf("cola=%d drops=%+v", len(p.q), d)
	}
}

func TestSubmitCountsEachReason(t *testing.T) {
	r := newReloj()
	p := NewPipeline(PipelineConfig[string]{Limits: Limits{PerSource: 1, PerSourceBurst: 1, Global: 1, GlobalBurst: 2, Queue: 1}, Now: r.Now})
	submit(p, "10.0.0.1:1", "a") // pasa a la cola
	submit(p, "10.0.0.1:1", "b") // sin ficha del origen
	submit(p, "10.0.0.2:1", "c") // cola llena
	submit(p, "10.0.0.3:1", "d") // sin ficha global
	d := p.Drops()
	if d.PorOrigen != 1 || d.ColaLlena != 1 || d.Global != 1 || d.Total != 3 {
		t.Fatalf("%+v", d)
	}
}

// Un origen que inunda gasta su cubo y la cola no se la quita a otro que sí cabe en su tasa.
func TestPipelineBurstFromOneSourceLeavesRoomForAnother(t *testing.T) {
	r := newReloj()
	p := NewPipeline(PipelineConfig[string]{Limits: Limits{PerSource: 10, PerSourceBurst: 10, Global: 1000, Queue: 64}, Now: r.Now})
	for range 500 {
		submit(p, "10.0.0.1:1", "flood")
	}
	submit(p, "10.0.0.2:1", "otro")
	got := map[string]int{}
	for len(p.q) > 0 {
		got[<-p.q]++
	}
	if got["flood"] != 10 || got["otro"] != 1 {
		t.Fatalf("pasaron %v", got)
	}
	if d := p.Drops(); d.PorOrigen != 490 || d.Top[0].Source != "10.0.0.1" {
		t.Fatalf("%+v", d)
	}
}

// El consumidor ve todo lo encolado, y Stop vacía la cola antes de volver.
func TestPipelineStopDrainsQueueAndFileErrorCancels(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	p := NewPipeline(PipelineConfig[string]{Handle: func(s string) { mu.Lock(); seen = append(seen, s); mu.Unlock() }})
	p.Start()
	for _, s := range []string{"a", "b", "c"} {
		submit(p, "10.0.0.1:1", s)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatalf("seen = %v", seen)
	}
	// un archivo roto: el primer fallo cancela la escucha y se devuelve
	dir := t.TempDir() + "/s"
	w, err := NewWriter(Sink{Dir: dir, Template: "t_{fecha}", MaxFiles: 5}, r0)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	cancelled := 0
	var q *Pipeline[testMsg]
	q = NewPipeline(PipelineConfig[testMsg]{Writer: w, Cancel: func() { cancelled++ }, Handle: func(m testMsg) { q.Write(m) }})
	removeAll(t, dir)
	q.Start()
	submit(q, "10.0.0.1:1", msg("10.0.0.1:1", "x"))
	submit(q, "10.0.0.1:1", msg("10.0.0.1:1", "y"))
	if err := q.Stop(); err == nil || cancelled != 1 {
		t.Fatalf("err=%v cancelaciones=%d", err, cancelled)
	}
}

func r0() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }

func removeAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
}
