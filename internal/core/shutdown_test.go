package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func (h *harness) shutdown(t *testing.T) error {
	t.Helper()
	_, err := v1.NewCoreServiceClient(h.conn).Shutdown(ctx(t), &v1.ShutdownRequest{})
	return err
}

func (h *harness) sigueServiendo(t *testing.T) bool {
	t.Helper()
	select {
	case <-h.served:
		return false
	case <-time.After(300 * time.Millisecond):
		return true
	}
}

func TestShutdownSinTrabajoAuditaYTerminaServe(t *testing.T) {
	h := newHarness(t, nil)
	// Un suscriptor de eventos abierto (la UI siempre tiene uno) no es trabajo vivo.
	sc, cancel := context.WithCancel(ctx(t))
	defer cancel()
	if _, err := h.events.Subscribe(sc, &v1.SubscribeRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := h.shutdown(t); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	select {
	case <-h.served:
	case <-time.After(10 * time.Second):
		t.Fatal("Serve no terminó")
	}
	// Serve ya terminó: la auditoría se lee de la bitácora, no del RPC.
	var n int
	if err := h.core.db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'core.shutdown'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("core.shutdown auditado %d veces (%v)", n, err)
	}
}

func TestShutdownConTrabajoVivoSeNiega(t *testing.T) {
	h := newHarness(t, nil)
	job, _ := h.arm(t, h.ready(t)) // un trabajo de Patrol armado
	err := h.shutdown(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), job) {
		t.Fatalf("Shutdown = %v, quería FailedPrecondition con %s", err, job)
	}
	if !h.sigueServiendo(t) {
		t.Fatal("se apagó con trabajo vivo")
	}
	if strings.Contains(h.auditText(t), `"action":"core.shutdown"`) {
		t.Fatal("auditó core.shutdown sin apagar")
	}
}

func TestShutdownListaCadaFuenteDeTrabajo(t *testing.T) {
	h := newHarness(t, nil)
	h.core.addBusy(func(context.Context) []string { return []string{"assist run r1 (sw1)"} })
	err := h.shutdown(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "assist run r1 (sw1)") {
		t.Fatalf("Shutdown = %v", err)
	}
	if !h.sigueServiendo(t) {
		t.Fatal("se apagó con trabajo vivo")
	}
}

func TestShutdownSinAuditoriaNoApaga(t *testing.T) {
	h := newHarness(t, nil)
	h.core.db.Close()
	err := h.shutdown(t)
	if err == nil || status.Code(err) == codes.FailedPrecondition {
		t.Fatalf("Shutdown = %v, quería un error de auditoría", err)
	}
	if !h.sigueServiendo(t) {
		t.Fatal("se apagó sin poder auditar")
	}
}
