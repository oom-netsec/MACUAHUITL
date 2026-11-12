package engine

import (
	"context"
	"sync"
)

// RunFunc ejecuta una ronda contra un equipo.
type RunFunc func(ctx context.Context, round int, target string) error

// Runner limita las sesiones simultáneas de todos los trabajos y nunca abre
// dos sesiones al mismo equipo dentro de un trabajo (spec §6).
type Runner struct {
	sem   chan struct{}
	bus   *Bus
	mu    sync.Mutex
	locks map[string]*sync.Mutex // shortcut: crece con trabajo+equipo y no se limpia; liberar al cerrar trabajos si llega a importar
}

func NewRunner(maxSessions int, bus *Bus) *Runner {
	return &Runner{sem: make(chan struct{}, maxSessions), bus: bus, locks: map[string]*sync.Mutex{}}
}

func (r *Runner) lock(jobID, target string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := jobID + "\x00" + target
	if r.locks[k] == nil {
		r.locks[k] = &sync.Mutex{}
	}
	return r.locks[k]
}

// RunRound corre f para cada target y devuelve el error de cada uno (nil si terminó bien).
func (r *Runner) RunRound(ctx context.Context, jobID string, round int, targets []string, f RunFunc) map[string]error {
	var mu sync.Mutex
	res := make(map[string]error, len(targets))
	var wg sync.WaitGroup
	for _, tg := range targets {
		wg.Add(1)
		go func(tg string) {
			defer wg.Done()
			lk := r.lock(jobID, tg)
			lk.Lock()
			defer lk.Unlock()
			var err error
			select {
			case r.sem <- struct{}{}:
				err = f(ctx, round, tg)
				<-r.sem
			case <-ctx.Done():
				err = ctx.Err()
			}
			mu.Lock()
			res[tg] = err
			mu.Unlock()
		}(tg)
	}
	wg.Wait()
	return res
}
