package service

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// PendingMax es cuántas vistas previas esperan a la vez; la más vieja cede su lugar.
const PendingMax = 16

// Pending guarda lo que una vista previa de import dejó listo, con un token de un solo uso que vence.
type Pending[T any] struct {
	mu sync.Mutex
	m  map[string]pendingEntry[T]
}

type pendingEntry[T any] struct {
	v       T
	expires time.Time
}

// Add guarda v y devuelve su token y cuándo vence. Primero tira los vencidos y, si hay PendingMax, al más viejo.
func (p *Pending[T]) Add(now time.Time, ttl time.Duration, v T) (string, time.Time) {
	b := make([]byte, 16)
	rand.Read(b)
	tok, exp := hex.EncodeToString(b), now.Add(ttl)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]pendingEntry[T]{}
	}
	for k, e := range p.m {
		if now.After(e.expires) {
			delete(p.m, k)
		}
	}
	p.makeRoom()
	p.m[tok] = pendingEntry[T]{v, exp}
	return tok, exp
}

// makeRoom suelta al más viejo (el de menor vencimiento) hasta que quepa uno más. Requiere p.mu.
func (p *Pending[T]) makeRoom() {
	for len(p.m) >= PendingMax {
		var oldest string
		for k, e := range p.m {
			if oldest == "" || e.expires.Before(p.m[oldest].expires) {
				oldest = k
			}
		}
		delete(p.m, oldest)
	}
}

// Take saca el token bajo el lock: dos llamadas a la vez no pueden aplicar la misma vista previa. No mira el
// vencimiento; quien llama compara expires con su reloj.
func (p *Pending[T]) Take(token string) (T, time.Time, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.m[token]
	delete(p.m, token)
	return e.v, e.expires, ok
}

// Restore devuelve un token tomado cuando la decisión fue mala y se puede corregir; tampoco pasa del tope.
func (p *Pending[T]) Restore(token string, v T, expires time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.m == nil {
		p.m = map[string]pendingEntry[T]{}
	}
	p.makeRoom()
	p.m[token] = pendingEntry[T]{v, expires}
}
