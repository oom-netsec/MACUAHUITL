package ingest

import (
	"sync"
	"time"
)

// PipelineConfig arma un Pipeline. T es lo que el lector encola (un datagrama,
// un mensaje crudo...); Handle lo procesa en la gorutina del consumidor.
type PipelineConfig[T any] struct {
	Limits    Limits           // sin rellenar: NewPipeline aplica Effective
	Now       func() time.Time // reloj de cubos y descartes; nil = time.Now
	Writer    *Writer          // archivo; nil = sin archivo
	Cancel    func()           // se llama al fallar el archivo: sin dónde guardar no tiene sentido seguir escuchando en silencio
	Handle    func(T)          // siempre desde la misma gorutina
	OnDrops   func(Drops)      // acumulado; a lo más una vez por DropEvery y solo si cambió, más una al cerrar
	DropEvery time.Duration    // 1 s por defecto
}

// Pipeline une los lectores con el consumidor: topes de tasa, cola acotada y
// conteo de descartes. Los lectores nunca esperan al consumidor.
type Pipeline[T any] struct {
	c       PipelineConfig[T]
	lim     *limiter
	drops   *dropLog
	q       chan T
	err     error // primer fallo del archivo; solo lo escribe el consumidor
	wg      sync.WaitGroup
	quit    chan struct{}
	lastRep uint64
}

func NewPipeline[T any](c PipelineConfig[T]) *Pipeline[T] {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.DropEvery <= 0 {
		c.DropEvery = time.Second
	}
	l := c.Limits.Effective()
	return &Pipeline[T]{c: c, lim: newLimiter(l, c.Now()), drops: newDropLog(), q: make(chan T, l.Queue), quit: make(chan struct{})}
}

// Now es el reloj del pipeline, para que el lector ponga la hora a lo que encola.
func (p *Pipeline[T]) Now() time.Time { return p.c.Now() }

// Queue es la cola hacia el consumidor (para pruebas y para medir cuánto espera).
func (p *Pipeline[T]) Queue() <-chan T { return p.q }

// Admit aplica los topes de tasa al origen (from: "ip:puerto" o IP). Si no pasa,
// cuenta el descarte. key es el origen contado, para Enqueue.
func (p *Pipeline[T]) Admit(from string) (key string, ok bool) {
	now := p.c.Now()
	key, motivo := p.lim.allow(SourceIP(from), now)
	if motivo != "" {
		p.drops.add(motivo, key, now)
		return key, false
	}
	return key, true
}

// Enqueue encola sin esperar; con la cola llena cuenta un descarte «cola_llena» y devuelve false.
func (p *Pipeline[T]) Enqueue(key string, v T) bool {
	select {
	case p.q <- v:
		return true
	default:
		p.drops.add(dropCola, key, p.c.Now())
		return false
	}
}

// Write guarda el evento en el archivo. Solo para Handle: el primer fallo cancela la escucha.
func (p *Pipeline[T]) Write(r Record) {
	if p.c.Writer == nil || p.err != nil {
		return
	}
	if err := p.c.Writer.Write(r); err != nil {
		p.err = err
		if p.c.Cancel != nil {
			p.c.Cancel()
		}
	}
}

func (p *Pipeline[T]) Start() {
	p.wg.Add(2)
	go p.consume()
	go p.report()
}

// Stop espera a que el consumidor vacíe la cola, cierra los reportes con una
// última llamada y devuelve el fallo del archivo, si hubo. Los lectores ya terminaron.
func (p *Pipeline[T]) Stop() error {
	close(p.q)
	close(p.quit)
	p.wg.Wait()
	p.reportDrops(true)
	return p.err
}

// Drops es el acumulado de descartes hasta ahora.
func (p *Pipeline[T]) Drops() Drops { return p.drops.snapshot() }

func (p *Pipeline[T]) consume() {
	defer p.wg.Done()
	for v := range p.q {
		p.c.Handle(v)
	}
}

func (p *Pipeline[T]) report() {
	defer p.wg.Done()
	tk := time.NewTicker(p.c.DropEvery)
	defer tk.Stop()
	for {
		select {
		case <-tk.C:
			p.reportDrops(false)
		case <-p.quit:
			return
		}
	}
}

// reportDrops entrega el acumulado si cambió desde el último reporte; al cierre
// (final) lo entrega siempre que haya habido descartes.
func (p *Pipeline[T]) reportDrops(final bool) {
	if p.c.OnDrops == nil {
		return
	}
	d := p.drops.snapshot()
	if d.Total == 0 || (!final && d.Total == p.lastRep) {
		return
	}
	p.lastRep = d.Total
	p.c.OnDrops(d)
}
