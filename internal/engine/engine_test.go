package engine

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func targets(n int) []string {
	var t []string
	for i := 0; i < n; i++ {
		t = append(t, fmt.Sprintf("10.0.0.%d", i))
	}
	return t
}

func TestGlobalLimit(t *testing.T) {
	r := NewRunner(3, NewBus(16))
	var cur, peak atomic.Int32
	errs := r.RunRound(context.Background(), "j", 1, targets(10), func(ctx context.Context, round int, target string) error {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		cur.Add(-1)
		return nil
	})
	if peak.Load() > 3 || len(errs) != 10 {
		t.Fatalf("peak = %d, results = %d", peak.Load(), len(errs))
	}
}

func TestLimitSharedAcrossJobs(t *testing.T) {
	r := NewRunner(2, NewBus(16))
	var cur, peak atomic.Int32
	f := func(ctx context.Context, round int, target string) error {
		n := cur.Add(1)
		if n > peak.Load() {
			peak.Store(n)
		}
		time.Sleep(30 * time.Millisecond)
		cur.Add(-1)
		return nil
	}
	var wg sync.WaitGroup
	for _, j := range []string{"a", "b", "c"} {
		wg.Add(1)
		go func(j string) { defer wg.Done(); r.RunRound(context.Background(), j, 1, targets(3), f) }(j)
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Fatalf("peak = %d across jobs", peak.Load())
	}
}

func TestOneSessionPerTarget(t *testing.T) {
	r := NewRunner(10, NewBus(16))
	var cur atomic.Int32
	var overlap atomic.Bool
	f := func(ctx context.Context, round int, target string) error {
		if cur.Add(1) > 1 {
			overlap.Store(true)
		}
		time.Sleep(30 * time.Millisecond)
		cur.Add(-1)
		return nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.RunRound(context.Background(), "j", 1, []string{"10.0.0.1"}, f) }()
	}
	wg.Wait()
	if overlap.Load() {
		t.Fatal("two sessions to the same target at once")
	}
}

func TestRunRoundCollectsErrors(t *testing.T) {
	r := NewRunner(4, NewBus(16))
	errs := r.RunRound(context.Background(), "j", 1, []string{"a", "b"}, func(_ context.Context, _ int, tg string) error {
		if tg == "b" {
			return fmt.Errorf("boom")
		}
		return nil
	})
	if errs["a"] != nil || errs["b"] == nil {
		t.Fatalf("errs = %v", errs)
	}
}

func TestSlowSubscriberNeverBlocks(t *testing.T) {
	b := NewBus(4)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	start := time.Now()
	for i := 0; i < 10000; i++ {
		b.Publish(Event{JobID: "j", Kind: Progress, DeviceID: "d", Index: i})
	}
	b.Publish(Event{JobID: "j", Kind: JobState, State: "completed"})
	if time.Since(start) > time.Second {
		t.Fatalf("publish took %v", time.Since(start))
	}
	deadline := time.After(2 * time.Second)
	n := 0
	for {
		select {
		case e := <-ch:
			n++
			if e.Kind == JobState && e.State == "completed" {
				if n > 20 {
					t.Fatalf("progress not coalesced: %d events before completed", n)
				}
				return
			}
		case <-deadline:
			t.Fatal("completed event lost")
		}
	}
}

func TestSubscribeFilterAndCancel(t *testing.T) {
	b := NewBus(4)
	ch, cancel := b.Subscribe([]string{"a"})
	b.Publish(Event{JobID: "b", Kind: Warning})
	b.Publish(Event{JobID: "a", Kind: Warning, Detail: "ok"})
	if e := <-ch; e.JobID != "a" {
		t.Fatalf("got %+v", e)
	}
	cancel()
	if b.Subscribers() != 0 {
		t.Fatalf("subscribers = %d", b.Subscribers())
	}
	if _, open := <-ch; open {
		t.Fatal("channel not closed after cancel")
	}
}

func collect(ch <-chan Event, until func(Event) bool, max time.Duration) []Event {
	var out []Event
	timeout := time.After(max)
	for {
		select {
		case e, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, e)
			if until(e) {
				return out
			}
		case <-timeout:
			return out
		}
	}
}

func count(evs []Event, kind EventKind, detail string) int {
	n := 0
	for _, e := range evs {
		if e.Kind == kind && (detail == "" || e.Detail == detail) {
			n++
		}
	}
	return n
}

func done(e Event) bool {
	return e.Kind == JobState && (e.State == "completed" || e.State == "cancelled")
}

func newSched(t *testing.T) (*Scheduler, *Bus) {
	b := NewBus(64)
	s := NewScheduler(NewRunner(10, b), b, time.Now)
	s.Heartbeat = 50 * time.Millisecond
	return s, b
}

func TestRoundsLimit(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	var runs atomic.Int32
	err := s.Arm("j", Schedule{Interval: 20 * time.Millisecond, Rounds: 3}, time.Now().Add(time.Minute), []string{"x"}, func(context.Context, int, string) error {
		runs.Add(1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	collect(ch, done, 2*time.Second)
	if runs.Load() != 3 {
		t.Fatalf("runs = %d", runs.Load())
	}
}

func TestOverlappingRoundSkipped(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	s.Arm("j", Schedule{Interval: 100 * time.Millisecond, Rounds: 3}, time.Now().Add(time.Minute), []string{"x"}, func(context.Context, int, string) error {
		time.Sleep(250 * time.Millisecond)
		return nil
	})
	evs := collect(ch, done, 3*time.Second)
	if count(evs, Warning, "round.skipped") == 0 {
		t.Fatalf("no round.skipped in %d events", len(evs))
	}
}

func TestPauseResume(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	var runs atomic.Int32
	s.Arm("j", Schedule{Interval: 40 * time.Millisecond, Rounds: 8}, time.Now().Add(time.Minute), []string{"x"}, func(context.Context, int, string) error {
		runs.Add(1)
		return nil
	})
	time.Sleep(10 * time.Millisecond)
	s.Pause("j")
	before := runs.Load()
	time.Sleep(130 * time.Millisecond)
	if runs.Load() != before {
		t.Fatalf("ran while paused: %d -> %d", before, runs.Load())
	}
	s.Resume("j")
	evs := collect(ch, done, 2*time.Second)
	if count(evs, Warning, "round.skipped") < 2 || runs.Load() <= before {
		t.Fatalf("skipped=%d runs=%d", count(evs, Warning, "round.skipped"), runs.Load())
	}
}

func TestHeartbeat(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	s.Arm("j", Schedule{Interval: time.Hour, Rounds: 2}, time.Now().Add(time.Minute), nil, func(context.Context, int, string) error { return nil })
	defer s.Cancel("j")
	evs := collect(ch, func(Event) bool { return false }, 180*time.Millisecond)
	if count(evs, Heartbeat, "") < 2 {
		t.Fatalf("heartbeats = %d", count(evs, Heartbeat, ""))
	}
}

func TestUntilStops(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	var runs atomic.Int32
	s.Arm("j", Schedule{Interval: 30 * time.Millisecond}, time.Now().Add(100*time.Millisecond), []string{"x"}, func(context.Context, int, string) error {
		runs.Add(1)
		return nil
	})
	evs := collect(ch, done, 2*time.Second)
	if n := runs.Load(); n < 2 || n > 5 || evs[len(evs)-1].State != "completed" {
		t.Fatalf("runs = %d, last = %+v", n, evs[len(evs)-1])
	}
}

func TestCancel(t *testing.T) {
	s, b := newSched(t)
	ch, cancel := b.Subscribe(nil)
	defer cancel()
	s.Arm("j", Schedule{Interval: time.Hour, Rounds: 5}, time.Now().Add(time.Minute), nil, func(context.Context, int, string) error { return nil })
	s.Cancel("j")
	evs := collect(ch, done, time.Second)
	if len(evs) == 0 || evs[len(evs)-1].State != "cancelled" {
		t.Fatalf("events = %+v", evs)
	}
}

func TestArmValidation(t *testing.T) {
	s, _ := newSched(t)
	f := func(context.Context, int, string) error { return nil }
	for name, sc := range map[string]Schedule{
		"cron inválido":      {Cron: "esto no"},
		"intervalo y cron":   {Interval: time.Second, Cron: "* * * * *"},
		"intervalo negativo": {Interval: -time.Second},
	} {
		if err := s.Arm(name, sc, time.Now().Add(time.Minute), nil, f); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := s.Arm("past", Schedule{}, time.Now().Add(-time.Second), nil, f); err == nil {
		t.Error("until in the past accepted")
	}
	s.Arm("dup", Schedule{Interval: time.Hour, Rounds: 2}, time.Now().Add(time.Minute), nil, f)
	defer s.Cancel("dup")
	if err := s.Arm("dup", Schedule{Interval: time.Hour}, time.Now().Add(time.Minute), nil, f); err == nil {
		t.Error("double arm accepted")
	}
}
