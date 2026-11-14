package core

import (
	"context"
	"io"
	"slices"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/engine"
)

func (h *harness) jobClosed(job string) bool {
	h.core.mu.Lock()
	defer h.core.mu.Unlock()
	return h.core.jobs[job].closed
}

// closedJob arma, cancela y espera a que el trabajo cierre de verdad (manifest y zip hechos).
func (h *harness) closedJob(t *testing.T) string {
	t.Helper()
	job, _ := h.arm(t, h.ready(t))
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job}); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(30 * time.Second); !h.jobClosed(job); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("el trabajo no cerró")
		}
	}
	return job
}

// Suscribirse a un trabajo ya cerrado manda su estado final y un closed con hora, y cierra el stream.
func TestSubscribeATrabajoCerradoMandaFinalYClosedYCierra(t *testing.T) { suscribirCerrado(t, 1) }

// Con el mismo id repetido en la petición, el cierre por «todos cerrados» funciona igual.
func TestSubscribeConIdRepetidoDeTrabajoCerradoCierra(t *testing.T) { suscribirCerrado(t, 2) }

func suscribirCerrado(t *testing.T, veces int) {
	t.Helper()
	h := newHarness(t, nil)
	job := h.closedJob(t)
	c, stop := context.WithTimeout(ctx(t), 5*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: slices.Repeat([]string{job}, veces)})
	if err != nil {
		t.Fatal(err)
	}
	var states []string
	for {
		e, err := s.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("el stream debía terminar: %v (eventos %v)", err, states)
		}
		if e.JobId != job || e.At == nil || e.At.AsTime().IsZero() {
			t.Fatalf("evento sin trabajo u hora: %v", e)
		}
		states = append(states, e.GetJobStateChanged().GetState())
	}
	if !slices.Equal(states, []string{"cancelled", "closed"}) {
		t.Fatalf("eventos = %v", states)
	}
}

// Un Subscribe que llega mientras finish corre (estado final puesto, closed aún no) no se cierra: recibe el closed por el bus.
func TestSubscribeDuranteFinishRecibeClosed(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.created(t, h.ready(t), nil)
	h.core.mu.Lock()
	h.core.jobs[job].state = "completed" // finish en curso: estado puesto, manifest y zip pendientes
	h.core.mu.Unlock()
	c, stop := context.WithTimeout(ctx(t), 10*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan string, 4)
	go func() {
		for {
			e, err := s.Recv()
			if err != nil {
				got <- "fin:" + err.Error()
				return
			}
			got <- e.GetJobStateChanged().GetState()
		}
	}()
	select {
	case m := <-got:
		t.Fatalf("antes del closed llegó %q (cerró el stream o mandó un final)", m)
	case <-time.After(500 * time.Millisecond):
	}
	h.core.mu.Lock()
	h.core.jobs[job].closed = true
	h.core.mu.Unlock()
	h.core.bus.Publish(engine.Event{JobID: job, Kind: engine.JobState, State: "closed"})
	if m := <-got; m != "closed" {
		t.Fatalf("llegó %q", m)
	}
}

// Cancelar un trabajo creado (que nunca pasa por finish) publica cancelled y closed, y un Subscribe tardío lo ve cerrado.
func TestCancelJobCreadoPublicaCancelledYClosed(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.created(t, h.ready(t), nil)
	c, stop := context.WithTimeout(ctx(t), 10*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job}); err != nil {
		t.Fatal(err)
	}
	var states []string
	for len(states) < 2 || states[len(states)-1] != "closed" {
		e, err := s.Recv()
		if err != nil {
			t.Fatalf("%v (eventos %v)", err, states)
		}
		if js := e.GetJobStateChanged(); js != nil {
			states = append(states, js.State)
		}
	}
	if !slices.Equal(states, []string{"cancelled", "closed"}) {
		t.Fatalf("eventos = %v", states)
	}
	s2, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := s2.Recv(); err != nil {
			if err != io.EOF {
				t.Fatal(err)
			}
			break
		}
	}
}

// Con un trabajo real: tras el estado final llegan las fases de empaquetado y el closed, en ese orden.
func TestTrabajoRealEmiteEmpaquetadoAntesDeClosed(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.arm(t, h.ready(t))
	c, stop := context.WithTimeout(ctx(t), 30*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: []string{job}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job}); err != nil {
		t.Fatal(err)
	}
	var seq []string
	for {
		e, err := s.Recv()
		if err != nil {
			t.Fatalf("%v (eventos %v)", err, seq)
		}
		if js := e.GetJobStateChanged(); js != nil {
			seq = append(seq, js.State)
			if js.State == "closed" {
				break
			}
		}
		if p := e.GetPhaseAdded(); p != nil {
			seq = append(seq, p.Kind.String())
		}
	}
	iPack, iClosed := slices.Index(seq, "JOB_PHASE_KIND_PACKAGED"), slices.Index(seq, "closed")
	if iPack < 0 || iPack > iClosed || slices.Index(seq, "JOB_PHASE_KIND_CANCELLED") > iClosed {
		t.Fatalf("orden = %v", seq)
	}
}
