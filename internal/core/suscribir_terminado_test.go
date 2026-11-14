package core

import (
	"context"
	"io"
	"slices"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// Suscribirse a un trabajo ya terminado manda su estado final y cierra el stream: no queda abierto para siempre.
func TestSubscribeATrabajoTerminadoCierraConEstadoFinal(t *testing.T) {
	suscribirTerminado(t, 1)
}

// Con el mismo id repetido en la petición, el cierre por «todos terminados» funciona igual.
func TestSubscribeConIdRepetidoDeTrabajoTerminadoCierra(t *testing.T) {
	suscribirTerminado(t, 2)
}

func suscribirTerminado(t *testing.T, veces int) {
	t.Helper()
	h := newHarness(t, nil)
	cred := h.ready(t)
	job, _ := h.arm(t, cred)
	if _, err := h.patrol.CancelJob(ctx(t), &v1.CancelJobRequest{JobId: job}); err != nil {
		t.Fatal(err)
	}
	h.summaryUntil(t, job, func(s *v1.JobSummary) bool { return s.State == "cancelled" })
	c, stop := context.WithTimeout(ctx(t), 5*time.Second)
	defer stop()
	s, err := h.events.Subscribe(c, &v1.SubscribeRequest{JobIds: slices.Repeat([]string{job}, veces)})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Recv()
	if err != nil || e.GetJobStateChanged().GetState() != "cancelled" || e.JobId != job {
		t.Fatalf("primer evento: %v %v", e, err)
	}
	if _, err := s.Recv(); err != io.EOF {
		t.Fatalf("el stream debía terminar: %v", err)
	}
}
