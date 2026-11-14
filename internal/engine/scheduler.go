package engine

import (
	"context"
	"errors"
	"fmt"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"sync"
	"sync/atomic"
	"time"

	"github.com/robfig/cron/v3"
)

// Schedule es propio del motor; patrol lo traduce desde su Spec.
// Interval y Cron son excluyentes; sin ninguno es una sola ronda.
type Schedule struct {
	Interval time.Duration
	Rounds   int // 0 = sin límite (hasta Until)
	Until    time.Time
	Cron     string
}

type armed struct {
	cancel  context.CancelFunc
	paused  atomic.Bool
	running atomic.Bool
	next    atomic.Int64 // UnixNano de la siguiente ronda; 0 = no hay
	until   time.Time    // fin de la ventana, sin lectura monotónica
}

// Scheduler dispara rondas de trabajos armados.
type Scheduler struct {
	Heartbeat time.Duration // 5 s por defecto (spec §6)
	Tick      time.Duration // cada cuánto se compara el reloj de pared con la hora esperada; 1 s por defecto
	r         *Runner
	bus       *Bus
	now       func() time.Time
	mu        sync.Mutex
	jobs      map[string]*armed
}

func NewScheduler(r *Runner, bus *Bus, now func() time.Time) *Scheduler {
	return &Scheduler{Heartbeat: 5 * time.Second, Tick: time.Second, r: r, bus: bus, now: now, jobs: map[string]*armed{}}
}

// Arm empieza a correr jobID: la primera ronda sale de inmediato, salvo con cron,
// donde espera a la primera coincidencia.
func (s *Scheduler) Arm(jobID string, sc Schedule, until time.Time, targets []string, f RunFunc) error {
	if sc.Interval < 0 {
		return errors.New("engine: intervalo negativo")
	}
	if sc.Interval > 0 && sc.Cron != "" {
		return errors.New("engine: intervalo y cron son excluyentes")
	}
	var cs cron.Schedule
	if sc.Cron != "" {
		var err error
		if cs, err = cron.ParseStandard(sc.Cron); err != nil {
			return fmt.Errorf("engine: cron: %w", err)
		}
	}
	// Round(0) quita la lectura monotónica: en Linux no avanza con el sistema suspendido y compararía mal contra el reloj de pared.
	until = until.Round(0)
	if !sc.Until.IsZero() && sc.Until.Round(0).Before(until) {
		until = sc.Until.Round(0)
	}
	if !until.After(s.now()) {
		return i18n.New("engine.err.job_ended", nil)
	}
	if sc.Interval == 0 && sc.Cron == "" {
		sc.Rounds = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.jobs[jobID]; dup {
		return i18n.New("engine.err.armed", i18n.A("job", jobID))
	}
	ctx, cancel := context.WithCancel(context.Background())
	a := &armed{cancel: cancel, until: until}
	s.jobs[jobID] = a
	s.bus.Publish(Event{JobID: jobID, Kind: JobState, State: "armed"})
	go s.heartbeat(ctx, jobID)
	go s.loop(ctx, a, jobID, sc, cs, until, targets, f)
	return nil
}

func (s *Scheduler) heartbeat(ctx context.Context, jobID string) {
	t := time.NewTicker(s.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.bus.Publish(Event{JobID: jobID, Kind: Heartbeat})
		}
	}
}

func (s *Scheduler) loop(ctx context.Context, a *armed, jobID string, sc Schedule, cs cron.Schedule, until time.Time, targets []string, f RunFunc) {
	var wg sync.WaitGroup
	state := "completed"
	next := s.now().Round(0)
	if cs != nil {
		next = cs.Next(next) // cron: la primera ronda es la primera coincidencia, no ya
	}
	for round := 1; sc.Rounds == 0 || round <= sc.Rounds; round++ {
		wake := next
		a.next.Store(wake.UnixNano())
		if !wake.Before(until) { // una ronda justo al cerrar la ventana no corre: no se anuncia
			wake = until // no esperar al siguiente tic si el trabajo termina antes
			a.next.Store(0)
		}
		if !s.sleepUntil(ctx, wake) {
			state = "cancelled"
		}
		if state == "cancelled" || !s.now().Before(until) {
			break
		}
		// La siguiente se calcula y publica antes de lanzar esta ronda: NextRound nunca devuelve la que ya corre.
		if cs != nil {
			next = cs.Next(s.now().Round(0))
		} else {
			next = next.Add(sc.Interval)
		}
		more := (sc.Rounds == 0 || round < sc.Rounds) && next.Before(until)
		if more {
			a.next.Store(next.UnixNano())
		} else {
			a.next.Store(0)
		}
		// Tras una suspensión del sistema, las rondas que ya pasaron de largo se registran como omitidas en vez de
		// salir todas de golpe; la última de la ventana sí corre.
		missed := more && sc.Interval > 0 && s.now().Round(0).Sub(wake.Round(0)) >= sc.Interval
		if a.paused.Load() || a.running.Load() || missed {
			s.bus.Publish(Event{JobID: jobID, Kind: Warning, Detail: "round.skipped", Index: round})
		} else {
			a.running.Store(true)
			wg.Add(1)
			go func(round int) {
				defer wg.Done()
				defer a.running.Store(false)
				s.bus.Publish(Event{JobID: jobID, Kind: JobState, State: "round.start", Index: round})
				s.r.RunRound(ctx, jobID, round, targets, f)
				s.bus.Publish(Event{JobID: jobID, Kind: JobState, State: "round.end", Index: round})
			}(round)
		}
	}
	a.next.Store(0)
	wg.Wait()
	if ctx.Err() != nil {
		state = "cancelled" // también si se canceló durante la última ronda
	}
	s.mu.Lock()
	delete(s.jobs, jobID)
	s.mu.Unlock()
	a.cancel()
	s.bus.Publish(Event{JobID: jobID, Kind: JobState, State: state})
}

// sleepUntil espera hasta wake mirando el reloj de pared cada Tick: los temporizadores de Go son monotónicos y no
// avanzan mientras el sistema está suspendido, así que un solo sueño largo se pasaría de la ventana al reanudar.
// Devuelve false si ctx se cancela antes.
func (s *Scheduler) sleepUntil(ctx context.Context, wake time.Time) bool {
	tick := s.Tick
	if tick <= 0 {
		tick = time.Second
	}
	for {
		rem := wake.Round(0).Sub(s.now().Round(0)) // Round(0) quita la lectura monotónica
		if rem <= 0 {
			return ctx.Err() == nil
		}
		t := time.NewTimer(min(rem, tick))
		select {
		case <-ctx.Done():
			t.Stop()
			return false
		case <-t.C:
		}
	}
}

func (s *Scheduler) get(jobID string) *armed {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jobs[jobID]
}

// NextRound es la hora de la siguiente ronda programada; cero si no hay o el trabajo no está armado.
func (s *Scheduler) NextRound(jobID string) time.Time {
	if a := s.get(jobID); a != nil {
		if n := a.next.Load(); n != 0 {
			return time.Unix(0, n)
		}
	}
	return time.Time{}
}

// Cancel detiene el trabajo; la ronda en curso recibe el contexto cancelado.
func (s *Scheduler) Cancel(jobID string) {
	if a := s.get(jobID); a != nil {
		a.cancel()
	}
}

// Pause hace que las rondas se registren como omitidas (bóveda cerrada).
func (s *Scheduler) Pause(jobID string) {
	if a := s.get(jobID); a != nil {
		a.paused.Store(true)
	}
}

func (s *Scheduler) Resume(jobID string) {
	if a := s.get(jobID); a != nil {
		a.paused.Store(false)
	}
}
