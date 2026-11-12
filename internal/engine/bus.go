// Package engine contiene el Scheduler, el Runner (semáforo global y un
// worker por equipo) y el EventBus (spec §6).
//
// No hace: hablar con equipos; recibe una RunFunc que lo hace.
package engine

import (
	"sync"
	"time"
)

type EventKind int

const (
	DeviceState EventKind = iota
	Progress
	Heartbeat
	JobState
	Warning
	Phase // fase nueva del historial: State = nombre de la fase, Index = ronda
)

type Event struct {
	At           time.Time
	JobID        string
	Kind         EventKind
	DeviceID     string
	State        string
	Command      string
	Index, Total int
	Bytes        int64
	Detail       string
}

// Bus reparte eventos sin bloquear nunca a quien publica. Por suscriptor, los
// Progress de un mismo equipo se combinan (gana el último); el resto se encola sin perderse.
type Bus struct {
	buffer int
	mu     sync.Mutex
	next   int
	subs   map[int]*sub
}

type sub struct {
	jobs     map[string]bool
	out      chan Event
	mu       sync.Mutex
	cond     *sync.Cond
	queue    []Event
	progress map[string]Event // último Progress pendiente por trabajo+equipo
	closed   bool
}

func NewBus(buffer int) *Bus { return &Bus{buffer: buffer, subs: map[int]*sub{}} }

// Subscribe devuelve un canal con los eventos de jobIDs (vacío = todos) y una función para cancelar.
func (b *Bus) Subscribe(jobIDs []string) (<-chan Event, func()) {
	s := &sub{out: make(chan Event, b.buffer), progress: map[string]Event{}}
	s.cond = sync.NewCond(&s.mu)
	if len(jobIDs) > 0 {
		s.jobs = map[string]bool{}
		for _, j := range jobIDs {
			s.jobs[j] = true
		}
	}
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = s
	b.mu.Unlock()
	go s.drain()
	var once sync.Once
	return s.out, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, id)
			b.mu.Unlock()
			s.mu.Lock()
			s.closed = true
			s.cond.Broadcast()
			s.mu.Unlock()
		})
	}
}

// Subscribers cuenta los suscriptores activos.
func (b *Bus) Subscribers() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

func (b *Bus) Publish(e Event) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	b.mu.Lock()
	subs := make([]*sub, 0, len(b.subs))
	for _, s := range b.subs {
		if s.jobs == nil || s.jobs[e.JobID] {
			subs = append(subs, s)
		}
	}
	b.mu.Unlock()
	for _, s := range subs {
		s.push(e)
	}
}

func (s *sub) push(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if e.Kind == Progress {
		key := e.JobID + "\x00" + e.DeviceID
		if _, pending := s.progress[key]; !pending {
			s.queue = append(s.queue, Event{Kind: Progress, JobID: e.JobID, DeviceID: e.DeviceID}) // marcador
		}
		s.progress[key] = e
	} else {
		s.queue = append(s.queue, e)
	}
	s.cond.Signal()
}

func (s *sub) drain() {
	defer close(s.out)
	for {
		s.mu.Lock()
		for len(s.queue) == 0 && !s.closed {
			s.cond.Wait()
		}
		if s.closed {
			s.mu.Unlock()
			return
		}
		e := s.queue[0]
		s.queue = s.queue[1:]
		if e.Kind == Progress {
			key := e.JobID + "\x00" + e.DeviceID
			e = s.progress[key]
			delete(s.progress, key)
		}
		s.mu.Unlock()
		for sent := false; !sent; {
			select {
			case s.out <- e:
				sent = true
			case <-time.After(100 * time.Millisecond):
				s.mu.Lock()
				closed := s.closed
				s.mu.Unlock()
				if closed {
					return
				}
			}
		}
	}
}
