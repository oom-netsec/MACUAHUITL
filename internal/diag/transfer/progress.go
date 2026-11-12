package transfer

import (
	"io"
	"sync"
	"time"
)

// Progress es el avance de una transferencia. Total es 0 si no se conoce.
type Progress struct {
	Bytes       int64
	Total       int64
	BytesPerSec float64 // promedio móvil de la velocidad reciente
}

// ProgressEvery es el intervalo mínimo entre avisos: a lo más 10 por segundo, para no saturar la vista.
const ProgressEvery = 100 * time.Millisecond

// progressTracker avisa el avance sin pasar de 10 avisos por segundo; el primero sale de inmediato y
// finish manda el último. Un rastreador nulo no hace nada.
type progressTracker struct {
	fn        func(Progress)
	now       func() time.Time
	mu        sync.Mutex
	bytes     int64
	total     int64
	last      time.Time
	lastBytes int64
	speed     float64
	sent      bool
	finished  bool
}

func newTracker(fn func(Progress), now func() time.Time) *progressTracker {
	if fn == nil {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &progressTracker{fn: fn, now: now}
}

func (p *progressTracker) setTotal(n int64) {
	if p == nil || n <= 0 {
		return
	}
	p.mu.Lock()
	p.total = n
	p.mu.Unlock()
}

func (p *progressTracker) add(n int64) {
	if p == nil || n <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bytes += n
	now := p.now()
	if p.sent && now.Sub(p.last) < ProgressEvery {
		return
	}
	p.emit(now)
}

// emit manda un aviso; quien llama tiene el candado.
func (p *progressTracker) emit(now time.Time) {
	if p.sent {
		if dt := now.Sub(p.last).Seconds(); dt > 0 {
			inst := float64(p.bytes-p.lastBytes) / dt
			if p.speed == 0 {
				p.speed = inst
			} else {
				p.speed = 0.3*inst + 0.7*p.speed
			}
		}
	}
	p.sent, p.last, p.lastBytes = true, now, p.bytes
	p.fn(Progress{Bytes: p.bytes, Total: p.total, BytesPerSec: p.speed})
}

// finish manda el aviso final con todo lo transferido.
func (p *progressTracker) finish() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.finished {
		return
	}
	p.finished = true
	p.emit(p.now())
}

// progressReader cuenta lo que se lee (envíos).
type progressReader struct {
	r io.Reader
	p *progressTracker
}

func (pr progressReader) Read(b []byte) (int, error) {
	n, err := pr.r.Read(b)
	pr.p.add(int64(n))
	return n, err
}
