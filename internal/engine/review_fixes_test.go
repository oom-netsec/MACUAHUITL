package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCancelDuringLastRoundIsCancelled(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	started := make(chan struct{})
	s.Arm("j", Schedule{}, time.Now().Add(time.Minute), []string{"x"}, func(ctx context.Context, _ int, _ string) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	})
	<-started
	s.Cancel("j")
	evs := collect(ch, done, 2*time.Second)
	if last := evs[len(evs)-1]; last.State != "cancelled" {
		t.Fatalf("final state = %q", last.State)
	}
}

func TestStopsAtUntilNotNextTick(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	start := time.Now()
	s.Arm("j", Schedule{Interval: 2 * time.Second}, time.Now().Add(200*time.Millisecond), nil, func(context.Context, int, string) error { return nil })
	collect(ch, done, 3*time.Second)
	if el := time.Since(start); el > time.Second {
		t.Fatalf("job ended %v after arm, want ~200ms", el)
	}
}

func TestCronWaitsForFirstMatch(t *testing.T) {
	s, _ := newSched(t)
	var runs atomic.Int32
	if err := s.Arm("j", Schedule{Cron: "0 0 1 1 *"}, time.Now().Add(time.Hour), []string{"x"}, func(context.Context, int, string) error {
		runs.Add(1)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer s.Cancel("j")
	time.Sleep(100 * time.Millisecond)
	if runs.Load() != 0 {
		t.Fatal("cron job ran immediately on Arm")
	}
}

func TestNextRound(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	start := time.Now()
	s.Arm("j", Schedule{Interval: time.Hour, Rounds: 2}, start.Add(3*time.Hour), []string{"x"}, func(context.Context, int, string) error { return nil })
	collect(ch, func(e Event) bool { return e.State == "round.end" }, 2*time.Second)
	deadline := time.Now().Add(2 * time.Second)
	for s.NextRound("j").IsZero() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if n := s.NextRound("j"); n.Sub(start) < 59*time.Minute || n.Sub(start) > 61*time.Minute {
		t.Fatalf("next = %v, want ~1h after arm", n.Sub(start))
	}
	// Una ventana que acaba antes de la siguiente ronda no tiene siguiente ronda.
	s.Arm("k", Schedule{Interval: time.Hour, Rounds: 2}, time.Now().Add(time.Minute), []string{"x"}, func(context.Context, int, string) error { return nil })
	collect(ch, func(e Event) bool { return e.JobID == "k" && e.State == "round.end" }, 2*time.Second)
	if n := s.NextRound("k"); !n.IsZero() {
		t.Fatalf("next = %v, want zero", n)
	}
	s.Cancel("j")
	s.Cancel("k")
	collect(ch, func(e Event) bool { return e.JobID == "j" && done(e) }, 2*time.Second)
	if n := s.NextRound("j"); !n.IsZero() {
		t.Fatalf("after cancel next = %v", n)
	}
}

// Mientras corre una ronda, NextRound ya da la siguiente (no la que corre), y en la última da cero.
func TestNextRoundDuranteLaRonda(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	release := make(chan struct{})
	start := time.Now()
	s.Arm("j", Schedule{Interval: time.Hour, Rounds: 2}, start.Add(3*time.Hour), []string{"x"}, func(context.Context, int, string) error {
		<-release
		return nil
	})
	collect(ch, func(e Event) bool { return e.State == "round.start" }, 2*time.Second)
	n := s.NextRound("j")
	close(release)
	if n.Sub(start) < 59*time.Minute || n.Sub(start) > 61*time.Minute {
		t.Fatalf("durante la ronda 1, next = %v después de armar; want ~1h", n.Sub(start))
	}
	s.Cancel("j")
	collect(ch, func(e Event) bool { return e.JobID == "j" && done(e) }, 2*time.Second)

	last := make(chan struct{})
	s.Arm("u", Schedule{Interval: time.Hour, Rounds: 1}, time.Now().Add(3*time.Hour), []string{"x"}, func(context.Context, int, string) error {
		<-last
		return nil
	})
	collect(ch, func(e Event) bool { return e.JobID == "u" && e.State == "round.start" }, 2*time.Second)
	n = s.NextRound("u")
	close(last)
	if !n.IsZero() {
		t.Fatalf("durante la última ronda, next = %v; want cero", n)
	}
	collect(ch, func(e Event) bool { return e.JobID == "u" && done(e) }, 2*time.Second)
}
